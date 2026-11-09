use std::rc::Rc;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use glory::prelude::*;

pub(crate) use super::platform_io::{copy_text_to_clipboard, download_text_as_file};
use crate::presentation::widgets::{heading, line, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};
use crate::recovery_crypto::{
    generate_recovery_key, normalize_recovery_key_input, recovery_key_confirmation_matches,
};
use crate::state::LocalStateStore;
use crate::transport::auth::with_authed_api;

const MLS_RECOVERY_BACKUP_STATE_KEY: &str = "mls.recovery_backup.v1";
/// Entry cap for the after-write backup probe single-flight set. Keyed by
/// `(base_url, actor_id)`, so a single browser session only ever holds a couple
/// of entries; the cap just bounds a pathological key space.
const MLS_BACKUP_AFTER_WRITE_PROBE_MAX_ENTRIES: usize = 64;
static MLS_BACKUP_AFTER_WRITE_PROBES: LazyLock<Mutex<crate::keyed_cooldown::SeenSet>> =
    LazyLock::new(|| {
        Mutex::new(crate::keyed_cooldown::SeenSet::new(
            MLS_BACKUP_AFTER_WRITE_PROBE_MAX_ENTRIES,
        ))
    });
pub(super) fn try_set_state<T: 'static>(state: Cage<T>, value: impl Into<T>) {
    let _ = state.try_revise(|current| *current = value.into());
}
pub fn try_needs_mls_backup_state() -> Option<Cage<bool>> {
    crate::presentation::current_context().map(|context| context.needs_mls_backup)
}

/// Pull the human-readable localpart out of the account's primary personal
/// handle (`<prepared-localpart>:<lowercase-A-label-domain>`) for use in the recovery-key
/// download filename. Returns an empty string when no handle is known yet.
pub(crate) fn recovery_localpart_from_handles(handles: &[String]) -> String {
    handles
        .iter()
        .find_map(|handle| {
            crate::identity::handle::parse_user_handle(handle).map(|parsed| parsed.localpart)
        })
        .unwrap_or_default()
}

/// Build a per-account download filename for the recovery-key `.txt`, so that
/// multiple accounts (or repeated generations for one account) don't all land
/// as `arkret-recovery-key.txt` / `…(1).txt` in the Downloads folder, where the
/// 24 words become impossible to tell apart.
///
/// `localpart` is the human handle localpart (see
/// [`recovery_localpart_from_handles`]); it is sanitised to a filesystem-safe
/// stem (`:` from the wire handle is illegal on Windows, so the caller never
/// passes the full `<localpart>:<domain>` form). Falls back to the bare name
/// when the localpart is empty.
pub(crate) fn recovery_key_filename(localpart: &str) -> String {
    let sanitized: String = localpart
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect();
    // Strip leading/trailing separators so we never emit a dotfile
    // (`.foo.txt`) or a dangling dash.
    let sanitized = sanitized.trim_matches(|ch| ch == '-' || ch == '.');
    if sanitized.is_empty() {
        "arkret-recovery-key.txt".to_owned()
    } else {
        format!("arkret-recovery-key-{sanitized}.txt")
    }
}

pub(crate) fn recovery_key_filename_from_handles(handles: &[String]) -> String {
    let localpart = recovery_localpart_from_handles(handles);
    recovery_key_filename(&localpart)
}

fn mls_backup_after_write_probe_key(base_url: &str, actor_id: &str) -> String {
    format!(
        "{}|{}",
        base_url.trim().trim_end_matches('/'),
        actor_id.trim()
    )
}

fn mark_mls_backup_after_write_probe_started(key: String) -> bool {
    match MLS_BACKUP_AFTER_WRITE_PROBES.lock() {
        Ok(mut probes) => probes.mark(key),
        Err(_) => {
            // A poisoned lock cannot authorize another probe against corrupt
            // shared state.
            tracing::warn!("MLS backup after-write probe set lock poisoned; skipping probe");
            false
        }
    }
}

struct MlsBackupAfterWriteProbe(String);

impl Drop for MlsBackupAfterWriteProbe {
    fn drop(&mut self) {
        if let Ok(mut probes) = MLS_BACKUP_AFTER_WRITE_PROBES.lock() {
            probes.forget(&self.0);
        }
    }
}

fn recovery_backup_scope_matches(
    evidence_authority: &arkret_sdk::AccountId,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
) -> bool {
    evidence_authority == authority
        && crate::mls_api_helpers::principal_core_id(actor_id)
            .is_ok_and(|principal| principal == authority.principal_id)
}

pub(crate) fn mls_recovery_backup_configured(state_store: &LocalStateStore) -> bool {
    state_store
        .load_plain_local_data(MLS_RECOVERY_BACKUP_STATE_KEY)
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|value| {
            value
                .get("backup_id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .map(str::to_owned)
        })
        .is_some_and(|backup_id| !backup_id.is_empty())
}

pub(crate) fn mark_mls_recovery_backup_configured(
    state_store: &mut LocalStateStore,
    backup_id: &str,
) {
    if backup_id.trim().is_empty() {
        return;
    }
    let payload = serde_json::json!({
        "backup_id": backup_id,
        "configured_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
    });
    state_store.save_plain_local_data(MLS_RECOVERY_BACKUP_STATE_KEY, payload.to_string());
}

/// X11.2 — shared first-write trigger with the no-prompt path enabled. After a
/// successful encrypted write, detect a missing `mls_account_secret` backup;
/// once the user has confirmed a Recovery Key, its cached public key can seal
/// the backup without asking for the 24 words again. The local backup marker
/// also acts as the completion fence for concurrent probes: a stale probe that
/// started before Recovery Key setup completed must not turn the prompt back
/// on after setup uploaded the account-secret backup.
pub async fn maybe_auto_backup_mls_after_encrypted_write(
    context: Rc<InksonContext>,
    base_url: String,
    token: String,
    authority: arkret_sdk::AccountId,
    actor_id: String,
    device_id: String,
    state_store: crate::runtime::input::StateStoreHandle,
    needs_mls_backup: Cage<bool>,
) {
    maybe_backup_or_flag_mls_backup_after_encrypted_write(
        context,
        base_url,
        token,
        authority,
        actor_id,
        (device_id, state_store),
        needs_mls_backup,
    )
    .await;
}

async fn maybe_backup_or_flag_mls_backup_after_encrypted_write(
    context: Rc<InksonContext>,
    base_url: String,
    token: String,
    authority: arkret_sdk::AccountId,
    actor_id: String,
    auto_backup: (String, crate::runtime::input::StateStoreHandle),
    needs_mls_backup: Cage<bool>,
) {
    if base_url.trim().is_empty() || token.trim().is_empty() || actor_id.trim().is_empty() {
        return;
    }
    let generation = context.session_generation.get();
    let account = context.active_account.get();
    let state_store_for_completion_fence = auto_backup.1.clone();
    let backup_completed_while_probe_was_running =
        || state_store_for_completion_fence.read(mls_recovery_backup_configured);
    // Local account secret must exist (encryption has been used) — otherwise
    // there's nothing to back up yet.
    let has_local_secret = {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &authority)
            .map(|secret| secret.is_some())
            .unwrap_or(false)
    };
    if !has_local_secret {
        return;
    }
    let probe_key = mls_backup_after_write_probe_key(&base_url, &actor_id);
    if !mark_mls_backup_after_write_probe_started(probe_key.clone()) {
        return;
    }
    // The UI prompt is not a lock. Finish or cancellation must release the
    // probe so newly available confirmed recovery material can be backed up.
    let _probe = MlsBackupAfterWriteProbe(probe_key);
    // If this browser already confirmed a Recovery Key, use the cached public
    // key to seal the first account-secret backup without asking for the words
    // again. Missing public key falls through to the explicit prompt below.
    let auto_backup_inputs = {
        let (device_id, state_store) = &auto_backup;
        state_store.read(|store| {
            let recovery_public_key = crate::views::recovery::local_recovery_public_key(store)?;
            let recovery_material_evidence = store.recovery_material_evidence()?;
            if !recovery_backup_scope_matches(
                &recovery_material_evidence.account_id,
                &authority,
                &actor_id,
            ) || recovery_material_evidence.device_id.as_str() != device_id
            {
                return None;
            }
            Some((
                state_store.clone(),
                device_id.clone(),
                recovery_material_evidence,
                recovery_public_key,
            ))
        })
    };
    // Server must NOT already hold an `mls_account_secret` backup. (When it
    // does, the restore/unlock path owns the flow — backup and restore are
    // mutually exclusive by this exact check, so we can't double-prompt.)
    let actor_for_probe = actor_id.clone();
    let device_for_probe = auto_backup.0.clone();
    let payload = match with_authed_api(&base_url, token.clone(), |api| async move {
        crate::mls::account_recovery::fetch_mls_restore_payload_with_unlock_proof(
            &api,
            &actor_for_probe,
            &device_for_probe,
        )
        .await
    })
    .await
    {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(
                error = %err.display_diagnostic(),
                "MLS backup detection could not list key backups after encrypted write"
            );
            if !context.session_matches(generation, &account) {
                return;
            }
            if !context.session_matches(generation, &account) {
                return;
            }
            if backup_completed_while_probe_was_running() {
                try_set_state(needs_mls_backup, false);
            } else {
                try_set_state(needs_mls_backup, true);
            }
            return;
        }
    };
    if !context.session_matches(generation, &account) {
        return;
    }
    if let Some(existing_backup) =
        crate::mls::account_recovery::select_preferred_mls_account_secret_backup(&payload)
    {
        if let Some((state_store, ..)) = auto_backup_inputs.as_ref()
            && let Some(backup_id) = existing_backup
                .get("backup_id")
                .and_then(serde_json::Value::as_str)
        {
            state_store.write(|store| mark_mls_recovery_backup_configured(store, backup_id));
        }
        try_set_state(needs_mls_backup, false);
        return;
    }
    if let Some((state_store, device_id, recovery_material_evidence, recovery_public_key)) =
        auto_backup_inputs
    {
        let actor_for_upload = actor_id.clone();
        let device_for_upload = device_id.clone();
        let authority_for_upload = authority.clone();
        let principal_control_realm_id = recovery_material_evidence
            .principal_control_realm_id
            .clone();
        let upload_result = with_authed_api(&base_url, token.clone(), |api| async move {
            crate::recovery_flow::verify_recovery_authority_evidence(
                &api,
                &recovery_material_evidence,
            )
            .await?;
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_public_key(
                &api,
                secure_store.as_ref(),
                &authority_for_upload,
                &principal_control_realm_id,
                &actor_for_upload,
                &device_for_upload,
                &recovery_public_key,
            )
            .await
        })
        .await;
        if !context.session_matches(generation, &account) {
            return;
        }
        match upload_result {
            Ok(backup_id) => {
                state_store.write(|store| mark_mls_recovery_backup_configured(store, &backup_id));

                if context.session_matches(generation, &account) {
                    try_set_state(needs_mls_backup, false);
                }
                return;
            }
            Err(err) => {
                tracing::warn!(
                    error = %err.display_diagnostic(),
                    "automatic MLS account-secret backup with recovery public key failed"
                );
            }
        }
    }

    if backup_completed_while_probe_was_running() {
        try_set_state(needs_mls_backup, false);
    } else {
        try_set_state(needs_mls_backup, true);
    }
}

#[derive(Clone)]
struct BackupController {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    generated: Cage<String>,
    confirmation: Cage<String>,
    input: Cage<String>,
    status: Cage<String>,
    busy: Cage<bool>,
    copied: Cage<bool>,
    created: Cage<bool>,
    epoch: Cage<u64>,
}
impl BackupController {
    fn close(&self) {
        if self.busy.get() {
            return;
        }
        self.epoch.revise(|value| *value = value.wrapping_add(1));
        self.context.needs_mls_backup.revise(|value| *value = false);
    }
    fn start(&self, regenerate: bool) {
        if self.busy.get() {
            return;
        }
        let Some(scope) = self.owner.upgrade() else {
            return;
        };
        let Some(account) = self.context.active_account.get() else {
            return;
        };
        let configured =
            self.context.state_store.read(|store| {
                crate::views::recovery::local_recovery_key_fingerprint(store).is_some()
            }) || self.context.account_recovery_configured.get() == Some(true);
        let generated = self.generated.get();
        let generated_in_this_flow = regenerate || !generated.trim().is_empty() || !configured;
        let key = if regenerate || !configured && generated.is_empty() {
            let key = match generate_recovery_key() {
                Ok(value) => value,
                Err(error) => {
                    try_set_state(
                        self.status,
                        format!(
                            "{} {error}",
                            self.context.tr("mls_backup.status.generate_failed")
                        ),
                    );
                    return;
                }
            };
            if self
                .context
                .state_store
                .write(|store| {
                    crate::views::recovery::save_generated_recovery_key_metadata_in_store(
                        store, &key,
                    )
                })
                .is_none()
            {
                try_set_state(
                    self.status,
                    "Recovery Key generated, but local metadata could not be saved.",
                );
                return;
            }
            try_set_state(self.generated, key.clone());
            try_set_state(self.confirmation, String::new());
            try_set_state(self.copied, false);
            key
        } else if !generated.is_empty() {
            generated
        } else {
            self.input.get()
        };
        let Some(secret) = normalize_recovery_key_input(&key) else {
            try_set_state(
                self.status,
                self.context.tr("mls_backup.status.invalid_recovery_key"),
            );
            return;
        };
        let evidence = self
            .context
            .state_store
            .read(LocalStateStore::recovery_material_evidence);
        let Some(evidence) = evidence else {
            try_set_state(self.status, "Frozen PCR authority evidence is required");
            return;
        };
        let authority = account.authority.clone();
        let actor = account.did().to_string();
        let device = account.device_id.to_string();
        if !recovery_backup_scope_matches(&evidence.account_id, &authority, &actor)
            || evidence.device_id.as_str() != device
        {
            try_set_state(
                self.status,
                "Frozen PCR authority evidence does not match this account",
            );
            return;
        }
        let base = self.context.base_url.get();
        let token = self.context.token.get();
        let generation = self.context.session_generation.get();
        let active = self.context.active_account.get();
        let serial = self.epoch.get();
        let this = self.clone();
        try_set_state(self.busy, true);
        try_set_state(self.created, false);
        try_set_state(self.status, self.context.tr("mls_backup.status.uploading"));
        let _=scope.owner().spawn(async move {
            let result=with_authed_api(&base,token,|api|async move{
                crate::recovery_flow::verify_recovery_authority_evidence(&api,&evidence).await?;
                let secure=crate::secure_key_store::default_secure_key_store("inkson");
                let id=crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key(&api,secure.as_ref(),&authority,&evidence.principal_control_realm_id,&actor,&device,&secret).await?;
                Ok::<_,anyhow::Error>(id)
            }).await;
            if this.owner.upgrade().is_none()||!this.context.session_matches(generation,&active)||this.epoch.get()!=serial{return}
            match result {
                Ok(id)=>{
                    this.context.state_store.write(|store|mark_mls_recovery_backup_configured(store,&id));

                    if this.owner.upgrade().is_none()||!this.context.session_matches(generation,&active)||this.epoch.get()!=serial{return}
                    try_set_state(this.busy,false);try_set_state(this.created,true);try_set_state(this.status,this.context.tr("mls_backup.status.created"));
                    if !generated_in_this_flow {try_set_state(this.input,String::new());crate::runtime_helpers::sleep_for(Duration::from_millis(750)).await;if this.owner.upgrade().is_some()&&this.context.session_matches(generation,&active)&&this.epoch.get()==serial{this.close();}}
                },
                Err(error)=>{try_set_state(this.busy,false);try_set_state(this.status,error.display());}
            }
        });
    }
}
pub fn mls_backup_prompt(scope: &Scope, context: Rc<InksonContext>) -> View {
    let controller = BackupController {
        context: context.clone(),
        owner: scope.downgrade(),
        generated: scope.cage(String::new()),
        confirmation: scope.cage(String::new()),
        input: scope.cage(String::new()),
        status: scope.cage(String::new()),
        busy: scope.cage(false),
        copied: scope.cage(false),
        created: scope.cage(false),
        epoch: scope.cage(0),
    };
    let reset = controller.clone();
    let needed = context.needs_mls_backup;
    scope.effect(move || {
        if !needed.get() {
            try_set_state(reset.generated, String::new());
            try_set_state(reset.confirmation, String::new());
            try_set_state(reset.input, String::new());
            try_set_state(reset.status, String::new());
            try_set_state(reset.busy, false);
            try_set_state(reset.copied, false);
            try_set_state(reset.created, false);
        }
    });
    let source = scope.bond({
        let controller = controller.clone();
        let context = context.clone();
        move || {
            (
                needed.get(),
                controller.generated.get(),
                controller.created.get(),
                context.account_recovery_configured.get(),
                context.locale.get(),
            )
        }
    });
    reactive(
        source,
        move |scope, (needed, generated, created, server_configured, _)| {
            if !needed || context.active_account.get().is_none() {
                return Box::new(widget(|_| Ok(())));
            }
            let configured = context.state_store.read(|store| {
                crate::views::recovery::local_recovery_key_fingerprint(store).is_some()
            }) || server_configured == Some(true);
            let mut body = vec![
                paragraph(
                    "muted",
                    context.translated(
                        scope,
                        if configured {
                            "mls_backup.description_existing"
                        } else {
                            "mls_backup.description"
                        },
                    ),
                ),
                paragraph(
                    "muted",
                    context.translated(
                        scope,
                        if configured {
                            "mls_backup.warning.existing_key"
                        } else {
                            "mls_backup.warning.passphrase_loss"
                        },
                    ),
                ),
            ];
            if configured && generated.is_empty() && !created {
                body.push(crate::presentation::widgets::input_field(
                    context.clone(),
                    "mls-backup-existing-key",
                    context.translated(scope, "mls_backup.existing_key_label"),
                    controller.input,
                    Purpose::Text,
                ));
                body.push(paragraph(
                    "muted",
                    context.translated(scope, "mls_backup.existing_key_hint"),
                ));
            }
            if !generated.is_empty() {
                body.push(paragraph(
                    "",
                    context.translated(scope, "mls_backup.generated_key_label"),
                ));
                body.push(Box::new(
                    sapid::text_field()
                        .unstyled()
                        .class("input recovery-key-words")
                        .name(context.translated(scope, "mls_backup.generated_key_label"))
                        .multiline(true)
                        .readonly(true)
                        .value(generated.clone()),
                ) as View);
                let copy = controller.clone();
                let copied = controller.copied;
                let ctx = context.clone();
                let label = scope.bond(move || {
                    ctx.tr(if copied.get() {
                        "mls_backup.copy_key_done"
                    } else {
                        "mls_backup.copy_key"
                    })
                });
                let download = controller.clone();
                let key_for_download = generated.clone();
                body.push(line(
                    "mls-backup-key-actions",
                    vec![
                        Box::new(
                            sapid::button()
                                .unstyled()
                                .class("secondary")
                                .label(label)
                                .on_press(move || {
                                    copy_text_to_clipboard(&copy.generated.get());
                                    try_set_state(copy.copied, true);
                                }),
                        ),
                        Box::new(
                            sapid::button()
                                .unstyled()
                                .class("secondary")
                                .label(context.translated(scope, "mls_backup.download_key"))
                                .on_press(move || {
                                    let handle = download.context.account_primary_handle.get();
                                    download_text_as_file(
                                        &recovery_key_filename_from_handles(std::slice::from_ref(
                                            &handle,
                                        )),
                                        &key_for_download,
                                    );
                                }),
                        ),
                    ],
                ));
                body.push(paragraph(
                    "form-hint-warn",
                    context.translated(scope, "mls_backup.generated_key_warning"),
                ));
                body.push(crate::presentation::widgets::input_field(
                    context.clone(),
                    "mls-backup-confirm-key",
                    context.translated(scope, "mls_backup.confirm_key_label"),
                    controller.confirmation,
                    Purpose::Text,
                ));
                body.push(paragraph(
                    "muted",
                    context.translated(scope, "mls_backup.confirm_key_hint"),
                ));
            }
            body.push(paragraph("muted", controller.status));
            let busy = controller.busy;
            let enabled = scope.bond(move || !busy.get());
            let mut actions = Vec::<View>::new();
            if created && generated.is_empty() {
                let close = controller.clone();
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("primary")
                        .label(context.translated(scope, "mls_backup.button_done"))
                        .on_press(move || close.close()),
                ));
            } else if generated.is_empty() || !created {
                let submit = controller.clone();
                let state = controller.clone();
                let label = scope.bond(move || {
                    state.context.tr(if state.busy.get() {
                        "mls_backup.button_busy"
                    } else if !state.generated.get().is_empty() {
                        "mls_backup.button_retry"
                    } else if configured {
                        "mls_backup.button_existing"
                    } else {
                        "mls_backup.button_idle"
                    })
                });
                let state = controller.clone();
                let can_submit = scope.bond(move || {
                    !state.busy.get()
                        && !state.created.get()
                        && (!configured
                            || !state.input.get().trim().is_empty()
                            || !state.generated.get().is_empty())
                        && !state.context.base_url.get().trim().is_empty()
                        && !state.context.token.get().trim().is_empty()
                });
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("primary")
                        .label(label)
                        .enabled(can_submit)
                        .on_press(move || submit.start(false)),
                ));
                let close = controller.clone();
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("secondary")
                        .label(context.translated(scope, "mls_backup.button_dismiss"))
                        .enabled(enabled)
                        .on_press(move || close.close()),
                ));
            } else {
                let regenerate = controller.clone();
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("secondary")
                        .label(context.translated(scope, "mls_backup.button_regenerate"))
                        .enabled(enabled)
                        .on_press(move || regenerate.start(true)),
                ));
                let confirm = controller.clone();
                let confirmation = controller.confirmation;
                let enabled =
                    scope.bond(move || !busy.get() && !confirmation.get().trim().is_empty());
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("primary")
                        .label(context.translated(scope, "mls_backup.button_confirm_saved"))
                        .enabled(enabled)
                        .on_press(move || {
                            if !recovery_key_confirmation_matches(
                                &confirm.generated.get(),
                                &confirm.confirmation.get(),
                            ) {
                                try_set_state(
                                    confirm.status,
                                    confirm.context.tr("mls_backup.status.confirm_mismatch"),
                                );
                                return;
                            }
                            confirm.close();
                        }),
                ));
            }
            let content = stack(
                "modal event mls-recovery-modal mls-backup-banner",
                vec![
                    stack(
                        "modal-head event-head",
                        vec![
                            heading(3, "", context.translated(scope, "mls_backup.title")),
                            paragraph("muted", context.translated(scope, "mls_backup.subtitle")),
                        ],
                    ),
                    stack("modal-body mls-recovery-modal-body", body),
                    line("modal-foot mls-backup-row", actions),
                ],
            );
            let close = controller.clone();
            let mut content = Some(content);
            Box::new(
                sapid::dialog("mls-backup")
                    .unstyled()
                    .name(context.translated(scope, "mls_backup.aria_label"))
                    .open(true)
                    .show_trigger(false)
                    .show_close(false)
                    .on_dismiss(move |_| close.close())
                    .content(move || {
                        content
                            .take()
                            .unwrap_or_else(|| Box::new(widget(|_| Ok(()))))
                    }),
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{
        recovery_key_filename, recovery_key_filename_from_handles, recovery_localpart_from_handles,
    };

    #[test]
    fn recovery_backup_scope_projects_the_did_and_keeps_the_complete_account() {
        let authority = crate::test_support::authority("did:web:alice.example");
        assert!(super::recovery_backup_scope_matches(
            &authority,
            &authority,
            "did:web:alice.example",
        ));
        assert!(super::recovery_backup_scope_matches(
            &authority,
            &authority,
            authority.principal_id.as_str(),
        ));
        assert!(!super::recovery_backup_scope_matches(
            &authority,
            &authority,
            "did:web:bob.example",
        ));
        assert!(!super::recovery_backup_scope_matches(
            &authority,
            &authority,
            "not-a-principal",
        ));
        let other_station = crate::test_support::authority_at_station(
            "did:web:alice.example",
            "did:web:other-station.example",
        );
        assert!(!super::recovery_backup_scope_matches(
            &other_station,
            &authority,
            "did:web:alice.example",
        ));
    }

    #[test]
    fn account_backup_probe_releases_on_completion_or_cancellation() {
        let key = "test-account-backup-probe-release".to_owned();
        assert!(super::mark_mls_backup_after_write_probe_started(
            key.clone()
        ));
        let probe = super::MlsBackupAfterWriteProbe(key.clone());
        assert!(!super::mark_mls_backup_after_write_probe_started(
            key.clone()
        ));
        drop(probe);
        assert!(super::mark_mls_backup_after_write_probe_started(
            key.clone()
        ));
        drop(super::MlsBackupAfterWriteProbe(key));
    }

    #[test]
    fn localpart_comes_from_handle_not_did_ulid() {
        // The readable localpart is taken from the personal handle; the DID's
        // `:users:<ULID>` segment is never used.
        assert_eq!(
            recovery_localpart_from_handles(&["alice:example.com".to_owned()]),
            "alice"
        );
        // Punctuation allowed by the canonical localpart profile is preserved.
        assert_eq!(
            recovery_localpart_from_handles(&["bob.smith_1:example.com".to_owned()]),
            "bob.smith_1"
        );
        // A port is not part of the canonical handle domain.
        assert_eq!(
            recovery_localpart_from_handles(&["bob:example.com:8443".to_owned()]),
            ""
        );
        // First parseable handle wins; junk is skipped.
        assert_eq!(
            recovery_localpart_from_handles(&[
                "not a handle".to_owned(),
                "carol:example.com".to_owned(),
            ]),
            "carol"
        );
    }

    #[test]
    fn localpart_empty_when_no_usable_handle() {
        assert_eq!(recovery_localpart_from_handles(&[]), "");
        assert_eq!(
            recovery_localpart_from_handles(&["did:web:example.com:users:01ABC".to_owned()]),
            ""
        );
    }

    #[test]
    fn filename_uses_localpart() {
        assert_eq!(
            recovery_key_filename("alice"),
            "arkret-recovery-key-alice.txt"
        );
        assert_eq!(
            recovery_key_filename("bob.smith_1"),
            "arkret-recovery-key-bob.smith_1.txt"
        );
    }

    #[test]
    fn filename_sanitises_unsafe_chars_and_separators() {
        // `+`/`~` are valid in a localpart but become `-`; leading/trailing
        // separators are stripped so we never emit a dotfile or dangling dash.
        assert_eq!(
            recovery_key_filename("a+b~c"),
            "arkret-recovery-key-a-b-c.txt"
        );
        assert_eq!(
            recovery_key_filename(".hidden."),
            "arkret-recovery-key-hidden.txt"
        );
    }

    #[test]
    fn filename_from_handles_uses_primary_handle_localpart() {
        assert_eq!(
            recovery_key_filename_from_handles(&["alice:local.host".to_owned()]),
            "arkret-recovery-key-alice.txt"
        );
        assert_eq!(
            recovery_key_filename_from_handles(&[
                "did:web:local.host:users:01ABC".to_owned(),
                "bob:local.host".to_owned(),
            ],),
            "arkret-recovery-key-bob.txt"
        );
    }

    #[test]
    fn filename_falls_back_when_no_primary_handle() {
        assert_eq!(recovery_key_filename(""), "arkret-recovery-key.txt");
        assert_eq!(recovery_key_filename("   "), "arkret-recovery-key.txt");
        assert_eq!(
            recovery_key_filename_from_handles(&[]),
            "arkret-recovery-key.txt"
        );
    }
}
