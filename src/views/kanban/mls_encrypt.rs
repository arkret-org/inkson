use arkret_wire::event_kind_str;
use serde_json::{Value, json};

use super::model::*;
use super::{
    card_detail_update_patch, collect_encryptable_private_patch_values,
    kanban_plaintext_block_reason, replace_private_patch_values,
};
use crate::state::LocalStateStore;
use crate::transport::auth::with_authed_api;
use crate::views::helpers::short_protocol_id;

/// Marker retained in the private helper result so plaintext and encrypted
/// call sites share one shape. Content writes never author MLS transitions;
/// they consume the Station-accepted epoch or pause for reconciliation.
#[derive(Default, Debug)]
pub(super) struct EncryptedWriteMlsEvents;

/// An encrypted patch whose envelopes still need the epoch's group-state
/// reference.
///
/// The reference is the `event_id` of the already accepted Event that
/// established the epoch. Application content never substitutes a draft ref.
#[derive(Debug)]
pub(super) struct EncryptedPatchPlan {
    patch: Value,
    paths: Vec<String>,
    payloads: Vec<Value>,
    group_id: Option<arkret_sdk::MlsGroupId>,
    epoch: u64,
    accepted_group_state_ref: Option<String>,
}

impl EncryptedPatchPlan {
    /// A plaintext write: nothing to seal.
    fn plaintext(patch: Value) -> Self {
        Self {
            patch,
            paths: Vec::new(),
            payloads: Vec::new(),
            group_id: None,
            epoch: 0,
            accepted_group_state_ref: Some(String::new()),
        }
    }

    pub(super) fn is_plaintext(&self) -> bool {
        self.payloads.is_empty()
    }

    /// The reference this plan needs, given the Events this write authored.
    pub(super) fn resolve_group_state_ref(
        &self,
        commit: Option<&arkret_sdk::EventId>,
        genesis: Option<&arkret_sdk::EventId>,
    ) -> Result<String, String> {
        if let Some(accepted) = self.accepted_group_state_ref.as_ref() {
            return Ok(accepted.clone());
        }
        let _ = (commit, genesis);
        Err("encrypted write has no accepted group-state reference for its epoch".to_owned())
    }

    /// Seal every envelope against the accepted epoch reference.
    pub(super) fn seal(
        self,
        commit: Option<&arkret_sdk::EventId>,
        genesis: Option<&arkret_sdk::EventId>,
    ) -> Result<Value, String> {
        if self.is_plaintext() {
            return Ok(self.patch);
        }
        let group_state_ref = self.resolve_group_state_ref(commit, genesis)?;
        let group_state_ref = arkret_sdk::EventId::new(group_state_ref)
            .map_err(|error| format!("invalid patch group-state Event id: {error}"))?;
        let mut sealed = Vec::with_capacity(self.payloads.len());
        for value in &self.payloads {
            let payload = serde_json::from_value::<arkret_sdk::EncryptedPayload>(value.clone())
                .map_err(|error| format!("invalid encrypted patch payload: {error}"))?;
            if self.group_id.as_ref() != Some(&payload.group_id) || payload.epoch != self.epoch {
                return Err(
                    "encrypted patch values do not share one MLS group and epoch".to_owned(),
                );
            }
            if payload.pre_encryption_header.group_state_ref != group_state_ref {
                return Err(
                    "encrypted patch group-state reference changed after sealing".to_owned(),
                );
            }
            let envelope = arkret_sdk::mls::encrypted_envelope_from_payload(&payload)
                .map_err(|error| format!("build encrypted Strand patch envelope: {error}"))?;
            sealed.push(
                serde_json::to_value(envelope).map_err(|error| {
                    format!("serialize encrypted Strand patch envelope: {error}")
                })?,
            );
        }
        let mut patch = self.patch;
        replace_private_patch_values(&mut patch, &self.paths, sealed)?;
        Ok(patch)
    }
}

#[derive(Clone, Debug)]
pub(super) struct SidecarTrackWriteContext {
    pub sidecar_id: Option<arkret_sdk::SidecarId>,
    pub ready: bool,
}

fn active_scope_matches_write_identity(
    scope: &crate::secure_key_store::ActiveDeviceSeedScope,
    actor_id: &str,
    device_id: &str,
) -> bool {
    crate::mls_api_helpers::principal_core_id(actor_id).is_ok_and(|actor_core| {
        scope.authority.principal_id == actor_core && scope.device_id.as_str() == device_id
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn encrypt_private_card_detail_patch_values_for_effective_scope(
    patch: Value,
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
    device_id: &str,
    mut state_store: SyncSignal<LocalStateStore>,
    sidecar: Option<&SidecarTrackWriteContext>,
) -> Result<(EncryptedPatchPlan, EncryptedWriteMlsEvents), String> {
    let account_scope = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| "active account authority is unavailable".to_owned())?;
    if !active_scope_matches_write_identity(&account_scope, actor_id, device_id) {
        return Err("encrypted write identity does not match the active account".to_owned());
    }
    if !collect_encryptable_private_patch_values(&patch)?.is_empty() {
        let realm_id_typed = arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|error| format!("invalid card Realm id: {error}"))?;
        let effective_scope = match sidecar {
            Some(context) => arkret_sdk::ScopeRef::Sidecar {
                realm_id: realm_id_typed,
                sidecar_id: context
                    .sidecar_id
                    .clone()
                    .filter(|_| context.ready)
                    .ok_or_else(|| "Private Sidecar MLS access is not ready".to_owned())?,
            },
            None => arkret_sdk::ScopeRef::Realm {
                realm_id: realm_id_typed,
            },
        };
        // Do not hold the account state lock while reading the committed current
        // and restoring this device's private group. A concurrent accepted cut may
        // invalidate the UI probe before the click; authoring rechecks it here.
        let store_handle = crate::app::runtime_adapter::state_store_handle(state_store);
        let gate_input =
            crate::mls::send_gate::MlsSendGateInput::capture(&store_handle, &effective_scope);
        let gate = crate::mls::send_gate::resolve_restorable_mls_send_gate(
            &gate_input,
            &effective_scope,
            &account_scope.device_id,
        )
        .await
        .map_err(|error| error.to_string())?;
        if !matches!(gate, crate::mls::send_gate::MlsSendGate::Encrypted(_)) {
            return Err(
                "the scope has no accepted MLS group for encrypted card content".to_owned(),
            );
        }
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let mut store = state_store.write();
    encrypt_private_card_detail_patch_values_with_store_for_effective_scope(
        patch,
        realm_id,
        strand_id,
        actor_id,
        device_id,
        &mut store,
        secure_store.as_ref(),
        sidecar,
    )
    .await
}

#[cfg(test)]
pub(super) async fn encrypt_private_card_detail_patch_values_with_store(
    patch: Value,
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
    device_id: &str,
    state_store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<(EncryptedPatchPlan, EncryptedWriteMlsEvents), String> {
    encrypt_private_card_detail_patch_values_with_store_for_effective_scope(
        patch,
        realm_id,
        strand_id,
        actor_id,
        device_id,
        state_store,
        secure_store,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn encrypt_private_card_detail_patch_values_with_store_for_effective_scope(
    patch: Value,
    realm_id: &str,
    strand_id: &str,
    actor_id: &str,
    device_id: &str,
    state_store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    sidecar: Option<&SidecarTrackWriteContext>,
) -> Result<(EncryptedPatchPlan, EncryptedWriteMlsEvents), String> {
    let account_scope = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| "active account authority is unavailable".to_owned())?;
    if !active_scope_matches_write_identity(&account_scope, actor_id, device_id) {
        return Err("encrypted write identity does not match the active account".to_owned());
    }
    let authority = &account_scope.authority;
    let account_device_id = &account_scope.device_id;
    if let Some(sidecar) = sidecar
        && (!sidecar.ready || sidecar.sidecar_id.is_none())
    {
        return Err("Private Sidecar MLS access is not ready".to_owned());
    }
    let values = collect_encryptable_private_patch_values(&patch)?;
    if values.is_empty() {
        return Ok((
            EncryptedPatchPlan::plaintext(patch),
            EncryptedWriteMlsEvents,
        ));
    }
    let plaintext_values = values
        .iter()
        .map(|(_, bytes)| bytes.clone())
        .collect::<Vec<_>>();
    let sidecar_id = sidecar.and_then(|context| context.sidecar_id.as_ref());
    let effective_scope = match sidecar_id {
        Some(sidecar_id) => arkret_sdk::ScopeRef::Sidecar {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
                .map_err(|error| format!("invalid Sidecar Realm id: {error}"))?,
            sidecar_id: sidecar_id.clone(),
        },
        None => arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
                .map_err(|error| format!("invalid Realm id: {error}"))?,
        },
    };
    let snapshot = state_store
        .mls_checkpoint_for_scope(&effective_scope)
        .ok_or_else(|| "checkpoint-proven MLS group state is pending".to_owned())?;
    let accepted_group_state_ref = state_store
        .mls_group_state_ref_for_scope(&effective_scope, &snapshot.group_id, snapshot.epoch)
        .map_err(|_| {
            "MLS group-state Event must be accepted before encrypting a Strand update".to_owned()
        })?;
    let (_member_ids, encrypted_values) =
        crate::mls::runtime::encrypt_values_with_device_snapshot_for_effective_scope(
            state_store,
            secure_store,
            realm_id,
            authority,
            account_device_id,
            KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
            &plaintext_values,
            event_kind_str::STRAND_UPDATE,
            accepted_group_state_ref.clone(),
            None,
            sidecar_id,
        )
        .map_err(|err| err.user_message())?;
    let first_payload = encrypted_values
        .first()
        .cloned()
        .ok_or_else(|| "MLS encryption returned no encrypted patch values".to_owned())
        .and_then(|value| {
            serde_json::from_value::<arkret_sdk::EncryptedPayload>(value)
                .map_err(|error| format!("invalid encrypted patch payload: {error}"))
        })?;
    let accepted_group_state_ref = Some(accepted_group_state_ref.to_string());
    // X5.1 — encryption succeeded. Persist the author's own plaintext into
    // the local-only sidecar so a later re-projection (refresh / board
    // switch / live poll) can render the author's own content, which can
    // never be recovered by decrypting the author's own MLS ciphertext.
    // The stored value is the JSON-serialized patch *value* (the same
    // `plaintext_values` bytes that were just encrypted) as a UTF-8 string;
    // the read path parses it back with `serde_json::from_str` and feeds it
    // to `strand_body_display_text`, keeping write+read symmetric. This is
    // local-only and NEVER enters the op / `append_raw_operation` payload.
    //
    // Key the sidecar by the path the ENCRYPTED value lands on
    // (`content` -> `encrypted_content`), because that is the path the reader
    // resolves the envelope at; writer and reader must agree on one token.
    for (path, plaintext_bytes) in &values {
        if let Ok(plaintext_str) = std::str::from_utf8(plaintext_bytes) {
            state_store.save_private_plaintext(
                realm_id,
                strand_id,
                kanban_encrypted_patch_path(path),
                plaintext_str,
            );
        }
    }
    let paths = values.into_iter().map(|(path, _)| path).collect::<Vec<_>>();
    Ok((
        EncryptedPatchPlan {
            patch,
            paths,
            payloads: encrypted_values,
            group_id: Some(first_payload.group_id.clone()),
            epoch: first_payload.epoch,
            accepted_group_state_ref,
        },
        EncryptedWriteMlsEvents,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch_card_detail_update(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    current: KanbanCard,
    draft: CardDetailDraft,
    // R4: three-state security signal (see `kanban_plaintext_block_reason`).
    scope_security_encrypted: Option<bool>,
    sidecar_track_write: Option<SidecarTrackWriteContext>,
    synthesis_entry_id: Option<String>,
    synthesis_revision_body: Option<String>,
    _selected_card: Signal<Option<KanbanCard>>,
    mut state_store: SyncSignal<LocalStateStore>,
    mut board_status: Signal<String>,
) -> bool {
    let mut current = current;
    if arkret_sdk::StrandId::new(current.id.clone()).is_err() {
        let canonical_id = {
            let snapshot = state_store.read().load();
            event_derived_target_aliases(&snapshot.raw_operations)
                .get(&current.id)
                .cloned()
        };
        let Some(canonical_id) = canonical_id else {
            board_status
                .set("card creation is still awaiting its canonical Strand identity".to_owned());
            return false;
        };
        current.id = canonical_id;
    }
    if current.state != CardState::Synced {
        board_status.set(
            "card has a pending local write; wait for acceptance before editing again".to_owned(),
        );
        return false;
    }
    let patch = match card_detail_update_patch(&current, &draft) {
        Ok(patch) => patch,
        Err(msg) => {
            board_status.set(msg);
            return false;
        }
    };
    let api_token = token();
    let Some(_current_revision) = current.authoring_basis.clone() else {
        board_status
            .set("The complete current card value is not available for editing yet.".to_owned());
        return false;
    };
    let sidecar_effective_scope = match sidecar_track_write
        .as_ref()
        .and_then(|context| context.sidecar_id.as_ref())
    {
        Some(sidecar_id) => {
            let realm_id = match arkret_sdk::RealmId::new(realm_id.clone()) {
                Ok(realm_id) => realm_id,
                Err(error) => {
                    board_status.set(format!("invalid Sidecar Realm id: {error}"));
                    return false;
                }
            };
            Some(arkret_sdk::ScopeRef::Sidecar {
                realm_id,
                sidecar_id: sidecar_id.clone(),
            })
        }
        None => None,
    };
    let source_scope = match sidecar_effective_scope.clone() {
        Some(scope) => scope,
        None => match arkret_sdk::RealmId::new(realm_id.clone()) {
            Ok(realm_id) => arkret_sdk::ScopeRef::Realm { realm_id },
            Err(error) => {
                board_status.set(format!("invalid card Realm id: {error}"));
                return false;
            }
        },
    };
    // R4 fail-closed: when the Realm security state is unknown (`None`),
    // treat the scope as encrypted so we take the encrypt path rather than
    // emitting a plaintext patch. The plaintext-block guard below still
    // fails closed on the unknown state for any private content.
    let effective_security_encrypted = current
        .security_encrypted
        .unwrap_or_else(|| scope_security_encrypted.unwrap_or(true));
    let (patch_plan, _mls_events) = if effective_security_encrypted {
        let private_values = match collect_encryptable_private_patch_values(&patch) {
            Ok(values) => values,
            Err(error) => {
                board_status.set(error);
                return false;
            }
        };
        if !private_values.is_empty()
            && matches!(
                &source_scope,
                arkret_sdk::ScopeRef::Realm { .. } | arkret_sdk::ScopeRef::Circle { .. }
            )
        {
            let device = match arkret_sdk::DeviceId::new(device_id.clone()) {
                Ok(device) => device,
                Err(error) => {
                    board_status.set(format!("invalid card device: {error}"));
                    return false;
                }
            };
            let store = crate::app::runtime_adapter::state_store_handle(state_store);
            let input = crate::mls::send_gate::MlsSendGateInput::capture(&store, &source_scope);
            if let Err(error) = crate::mls::send_gate::resolve_restorable_mls_send_gate(
                &input,
                &source_scope,
                &device,
            )
            .await
            {
                board_status.set(format!("encrypted card write is not ready: {error}"));
                return false;
            }
        }
        match encrypt_private_card_detail_patch_values_for_effective_scope(
            patch,
            &realm_id,
            &current.id,
            &actor_id,
            &device_id,
            state_store,
            sidecar_track_write.as_ref(),
        )
        .await
        {
            Ok(result) => result,
            Err(msg) => {
                board_status.set(msg);
                return false;
            }
        }
    } else {
        (
            EncryptedPatchPlan::plaintext(patch),
            EncryptedWriteMlsEvents,
        )
    };
    // R4: feed the guard the three-state security signal. An explicit
    // per-card `security_encrypted` flag (`Some`) wins; otherwise fall back to
    // the scope three-state so an unknown projection fails closed.
    let guard_security_state = current
        .security_encrypted
        .map(Some)
        .unwrap_or(scope_security_encrypted);

    // Publish the full overlay before the editor closes, rather than waiting
    // for the detached submit task's first poll to populate its content.
    let sealed_patch = match patch_plan.seal(None, None) {
        Ok(patch) => patch,
        Err(error) => {
            board_status.set(format!("cannot seal card update: {error}"));
            return false;
        }
    };

    // Do not mutate the detail signal before acceptance. The durable queued
    // record drives the board overlay; terminal failures are excluded there,
    // so a rejected Event cannot leave UI state that never existed remotely.

    // The holder-local identity of this write. It is allocated before the Event
    // exists, which is exactly why the optimistic row can be keyed by it: the
    // Event id is only known after the epoch's Event has been authored.
    let local_operation_id = crate::operation::LocalOperationId::new();
    let operation_id = local_operation_id.to_string();
    let synthesis_entry_id = synthesis_revision_body
        .as_ref()
        .map(|_| synthesis_entry_id.unwrap_or_else(|| operation_id.clone()));
    let local_synthesis_revision_body = synthesis_revision_body
        .clone()
        .filter(|_| !effective_security_encrypted);
    let kind = event_kind_str::STRAND_UPDATE.to_owned();
    state_store.write().enqueue_local_projection_command(
        operation_id.clone(),
        Some(realm_id.clone()),
        json!({
            "kind": kind,
            "operation_id": operation_id.clone(),
            "actor_id": actor_id.clone(),
            "created_at": arkret_sdk::canonical::format_timestamp_canonical(
                crate::clock::now_utc_millis(),
            ),
            "write_state": "queued",
            "synthesis_entry_id": synthesis_entry_id,
            "synthesis_revision_body": local_synthesis_revision_body,
            "encrypted_payload_local": effective_security_encrypted,
            "body": {
                "strand_id": current.id,
                "patch": sealed_patch,
            },
        }),
    );
    state_store.write().project_pending_local_commands();
    board_status.set(format!(
        "submitting {kind} operation {}",
        short_protocol_id(&operation_id)
    ));
    // X11.2 — first-write trigger. Read the context-provided
    // `needs_mls_backup` signal HERE (inside the Dioxus scope), so the
    // encrypted-write success arm can flip the backup prompt on directly,
    // bypassing the fragile boot detection effect. Best-effort: `None` when
    // no provider is mounted (unit tests / non-app callers).
    let backup_trigger_signal = crate::components::try_needs_mls_backup_signal();
    let base_for_backup_trigger = base_url.clone();
    let actor_for_backup_trigger = actor_id.clone();
    let backup_account_scope = if effective_security_encrypted {
        match crate::secure_key_store::active_device_seed_scope() {
            Some(scope) if active_scope_matches_write_identity(&scope, &actor_id, &device_id) => {
                Some(scope)
            }
            Some(_) => {
                board_status.set("active account authority does not match card author".to_owned());
                return false;
            }
            None => {
                board_status.set("active account authority is unavailable".to_owned());
                return false;
            }
        }
    } else {
        None
    };
    let sidecar_effective_scope = sidecar_effective_scope.clone();
    let update_realm_id = realm_id.clone();
    let update_actor_id = actor_id.clone();
    let update_strand_id = current.id.clone();
    let submit_authority = match crate::app::SessionContext::get()
        .active_account
        .read()
        .as_ref()
        .map(|account| account.authority.clone())
    {
        Some(authority) => authority,
        None => {
            board_status.set("active account authority is unavailable".to_owned());
            return false;
        }
    };
    // Saving closes the editor immediately. A component-scoped task would be
    // cancelled as that edit subtree unmounts, leaving the durable operation
    // permanently queued and never sending its Event. Run the protocol
    // sequence at the root and retain only the app-owned state store across
    // awaits; component UI signals are deliberately not captured.
    let submit_state_store = crate::app::runtime_adapter::state_store_handle(state_store);
    dioxus::core::spawn_forever(async move {
        let submit_event = match build_card_detail_update_operation(
            &update_realm_id,
            &update_actor_id,
            &update_strand_id,
            sealed_patch,
        ) {
            Ok(op) => {
                let op = op.with_local_operation_id(local_operation_id);
                match sidecar_effective_scope.as_ref() {
                    Some(effective_scope) if effective_scope == &source_scope => {
                        op.with_effective_scope(effective_scope.clone())
                    }
                    Some(_) => Err(anyhow::anyhow!(
                        "the draft source belongs to a different effective scope"
                    )),
                    None => op.with_effective_scope(source_scope.clone()),
                }
            }
            Err(error) => Err(error),
        };
        let submit_event = match submit_event {
            Ok(op) => op,
            Err(error) => {
                let error = format!("cannot update card: {error:#}");
                submit_state_store.write(|store| {
                    store.update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(error.clone()),
                    );
                });
                tracing::warn!(%error, "cannot author encrypted card update");
                return;
            }
        };
        if let Some(reason) = kanban_plaintext_block_reason(guard_security_state, &submit_event) {
            submit_state_store.write(|store| {
                store.update_raw_operation_write_state(
                    &operation_id,
                    "failed",
                    None,
                    Some(reason.clone()),
                );
            });
            tracing::warn!(%reason, "encrypted card update blocked");
            return;
        }
        // The optimistic row was enqueued before the patch could be sealed, so
        // the body lands here, once it exists.
        submit_state_store.write(|store| {
            store.update_raw_operation_body(&operation_id, submit_event.payload_value());
        });
        let update_state_store = submit_state_store.clone();
        let update_authority = submit_authority.clone();
        match with_authed_api(&base_url, api_token.clone(), |api| async move {
            api.event_submitter()?
                .with_state_store(update_state_store)
                .with_authority(update_authority)
                .submit_sdk_event(&submit_event)
                .await
        })
        .await
        {
            Ok(resp) => {
                submit_state_store.write(|store| {
                    store.update_raw_operation_write_state(
                        &operation_id,
                        if resp.is_committed() {
                            "accepted"
                        } else {
                            "queued"
                        },
                        Some(resp.event_id.clone()),
                        None,
                    );
                });
                tracing::debug!(
                    kind = %kind,
                    event_id = %short_protocol_id(&resp.event_id),
                    "detached card update accepted by server"
                );
                if effective_security_encrypted {
                    let Some(backup_account_scope) = backup_account_scope else {
                        tracing::warn!(
                            "active account authority is unavailable after encrypted write"
                        );
                        return;
                    };
                    crate::components::schedule_mls_recovery_backups_after_encrypted_write(
                        base_for_backup_trigger.clone(),
                        api_token.clone(),
                        backup_account_scope.authority.clone(),
                        actor_for_backup_trigger.clone(),
                        backup_account_scope.device_id.to_string(),
                        state_store,
                    );
                    // X11.2 — first-write trigger. After this encrypted write
                    // landed, auto-back up the account secret when possible.
                    // The helper dedupes its server probe per account/session, so
                    // ordinary writes do not list backups repeatedly.
                    if let Some(signal) = backup_trigger_signal {
                        crate::components::maybe_auto_backup_mls_after_encrypted_write(
                            base_for_backup_trigger.clone(),
                            api_token.clone(),
                            backup_account_scope.authority.clone(),
                            actor_for_backup_trigger.clone(),
                            backup_account_scope.device_id.to_string(),
                            crate::app::runtime_adapter::state_store_handle(state_store),
                            signal,
                        )
                        .await;
                    }
                }
            }
            Err(err) => {
                let error = err.display().to_string();
                submit_state_store.write(|store| {
                    store.update_raw_operation_write_state(
                        &operation_id,
                        "failed",
                        None,
                        Some(error.clone()),
                    );
                });
                // §2.4.1 `epoch_update_required`: arm the coverage repair so the
                // per-Realm MLS effect advances the epoch. Without this the
                // refusal is just another failed write and the scope never
                // recovers.
                let paused = submit_state_store.write(|store| {
                    crate::mls::coverage_liveness::note_e2ee_submit_refusal_in_store(
                        store,
                        &realm_id,
                        None,
                        err.inner(),
                    )
                });
                if paused {
                    tracing::warn!(
                        kind = %kind,
                        "card update paused while MLS epoch advances to cover governance Seal"
                    );
                } else {
                    tracing::warn!(kind = %kind, %error, "detached card update failed");
                }
            }
        }
    });
    true
}

pub(super) fn build_card_detail_update_operation(
    realm_id: &str,
    actor_id: &str,
    strand_id: &str,
    patch: Value,
) -> anyhow::Result<crate::operation::LocalOperation> {
    crate::operation::ak_ops::strand_update_patch(realm_id, actor_id, strand_id, patch)?
        .build_sdk_event("inkson")
}
