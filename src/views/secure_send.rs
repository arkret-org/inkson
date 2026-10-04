//! Shared E2EE "Send Secure" pipeline.
//!
//! This module owns the MLS core + operation construction + message
//! submission used by the Chat discussion view to send an
//! encrypted `ak.message.create`. It was extracted from the verified Chat
//! "Send Secure" flow so encryption and durable ratchet persistence stay in
//! one path.
//!
//! Boundary: this module performs everything that MUST be identical across the
//! message-write path —
//!   1. MLS encrypt of the canonical Content Block bytes (`run_local_mls_encrypt` →
//!      `mls::runtime::encrypt_message_with_device_snapshot`),
//!   2. spec-canonical `ak.schema.encrypted_envelope.v1` wrap bound to the accepted group-state
//!      ref,
//!   3. `ak.message.create` payload build (with reply-to + message id),
//!   4. durable sender-ratchet persistence before submission.
//!
//! UI-shaped concerns stay in the caller: the optimistic bubble, draft
//! recovery, author-owned sidecar persistence, and status
//! text. The caller drives these off the typed [`SecureSendBuild`] /
//! [`SecureSendOutcome`] returned here.

use dioxus::prelude::*;

use crate::state::LocalStateStore;

pub(crate) type LocalMlsEncryptResult = crate::mls::runtime::DeviceSnapshotEncryption;

/// Ephemeral dependencies of the UI's read-only readiness probe.
#[derive(Clone, PartialEq)]
struct SendReadinessKey {
    scope: Option<arkret_sdk::ScopeRef>,
    device: arkret_sdk::DeviceId,
    authority: Option<arkret_sdk::AccountId>,
    generation: u64,
    reset_required: bool,
    detail_invalidated: bool,
    persistence_healthy: bool,
    private_root_available: bool,
    creator_revision: u64,
    checkpoint: Option<(
        u64,
        Option<arkret_sdk::EventId>,
        chrono::DateTime<chrono::Utc>,
    )>,
}

/// Never reuse a ready result across account, scope, cut or private-state changes.
pub(crate) fn use_scope_send_ready(
    state_store: SyncSignal<LocalStateStore>,
    scope: Option<arkret_sdk::ScopeRef>,
    device: arkret_sdk::DeviceId,
) -> bool {
    use_scope_send_gate(state_store, scope, device).is_some()
}

/// The body mode and readiness come from the same complete durable cut.
pub(crate) fn use_scope_send_gate(
    state_store: SyncSignal<LocalStateStore>,
    scope: Option<arkret_sdk::ScopeRef>,
    device: arkret_sdk::DeviceId,
) -> Option<crate::mls::send_gate::MlsSendGate> {
    use_scope_send_probe(state_store, scope, device).gate
}

pub(crate) struct ScopeSendProbe {
    pub gate: Option<crate::mls::send_gate::MlsSendGate>,
    pub checking: bool,
}

pub(crate) fn use_scope_send_probe(
    state_store: SyncSignal<LocalStateStore>,
    scope: Option<arkret_sdk::ScopeRef>,
    device: arkret_sdk::DeviceId,
) -> ScopeSendProbe {
    // Creator Ready is committed in its own vault, independently of the
    // account cursor and checkpoint. That commit must wake a blocked probe.
    let mut creator_revision = use_signal(|| 0_u64);
    use_future(move || async move {
        let mut changes = crate::outbound_store::subscribe_creator_committed_changes();
        loop {
            let revision = *changes.borrow_and_update();
            if *creator_revision.peek() != revision {
                creator_revision.set(revision);
            }
            if changes.changed().await.is_err() {
                break;
            }
        }
    });
    let key = use_memo(use_reactive((&scope, &device), move |(scope, device)| {
        let state = state_store.read();
        let authority = state.active_authority();
        let private_root_available = authority.as_ref().is_some_and(|authority| {
            let secure = crate::secure_key_store::default_secure_key_store("inkson");
            crate::mls::runtime::load_device_checkpoint_secret(secure.as_ref(), authority, &device)
                .is_ok()
        });
        let checkpoint = scope
            .as_ref()
            .and_then(|scope| state.durable_mls_checkpoint_for_scope(scope).ok().flatten())
            .map(|snapshot| {
                (
                    snapshot.epoch,
                    snapshot.group_state_event_id,
                    snapshot.recorded_at,
                )
            });
        let detail_invalidated = scope
            .as_ref()
            .and_then(arkret_sdk::ScopeRef::realm_id_opt)
            .is_none_or(|realm_id| state.realm_detail_invalidated(realm_id.as_str()));
        SendReadinessKey {
            scope,
            device,
            authority,
            generation: state.current_generation(),
            reset_required: state.current_reset_required(),
            detail_invalidated,
            persistence_healthy: state.persist_error().is_none(),
            private_root_available,
            creator_revision: creator_revision(),
            checkpoint,
        }
    }));
    let mut result =
        use_signal(|| None::<(SendReadinessKey, Option<crate::mls::send_gate::MlsSendGate>)>);
    use_effect(move || {
        let captured = key();
        spawn(async move {
            let gate = if let Some(scope) = captured.scope.as_ref().filter(|_| {
                !captured.reset_required
                    && !captured.detail_invalidated
                    && captured.persistence_healthy
            }) {
                let store = crate::app::runtime_adapter::state_store_handle(state_store);
                let input = crate::mls::send_gate::MlsSendGateInput::capture(&store, scope);
                let outcome = crate::mls::send_gate::resolve_restorable_mls_send_gate(
                    &input,
                    scope,
                    &captured.device,
                )
                .await;
                #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
                if let Err(error) = &outcome {
                    tracing::warn!(%error, "MLS send readiness probe failed");
                }
                outcome.ok()
            } else {
                None
            };
            if *key.peek() == captured {
                result.set(Some((captured, gate)));
            }
        });
    });
    let current_key = key();
    let result = result.read();
    let completed = result
        .as_ref()
        .filter(|(captured, _)| captured == &current_key);
    ScopeSendProbe {
        gate: completed.and_then(|(_, gate)| gate.clone()),
        checking: completed.is_none()
            && current_key.scope.is_some()
            && !current_key.reset_required
            && !current_key.detail_invalidated
            && current_key.persistence_healthy,
    }
}

/// Encrypt `plaintext_bytes` under the Realm MLS group and return the
/// structured MLS payload + the canonical AAD it was bound to. Epoch
/// transitions are reconciled separately; a content send only consumes an
/// already accepted group-state reference.
///
/// Runs on wasm: the underlying `mls::runtime::encrypt_message_with_device_snapshot`
/// uses the same wasm-enabled OpenMLS path as kanban strand-content encryption.
///
/// On any failure (missing Welcome/snapshot, restore fails, encrypt fails),
/// preserve the typed runtime error so the caller can surface the actual
/// fail-closed reason instead of a generic "could not produce" message.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_local_mls_encrypt(
    state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    plaintext_bytes: &[u8],
    metadata_plaintext_bytes: Option<&[u8]>,
    expected_sender_domain: Option<&str>,
    circle_id: Option<&str>,
    sidecar_id: Option<&arkret_sdk::SidecarId>,
) -> Result<LocalMlsEncryptResult, crate::mls::runtime::MlsRuntimeError> {
    serde_json::from_slice::<arkret_sdk::ContentBlock>(plaintext_bytes).map_err(|error| {
        crate::mls::runtime::MlsRuntimeError::Serialize(format!(
            "message plaintext is not a ContentBlock: {error}"
        ))
    })?;
    if let Some(metadata) = metadata_plaintext_bytes {
        serde_json::from_slice::<arkret_sdk::MessageMetadata>(metadata).map_err(|error| {
            crate::mls::runtime::MlsRuntimeError::Serialize(format!(
                "message metadata plaintext is not MessageMetadata: {error}"
            ))
        })?;
    }
    run_local_mls_encrypt_for_event(
        state_store,
        realm_id,
        authority,
        device_id,
        arkret_sdk::MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE,
        arkret_sdk::EventKind::MessageCreate.as_str(),
        plaintext_bytes,
        metadata_plaintext_bytes.map(|_| arkret_sdk::MESSAGE_METADATA_MLS_CONTENT_TYPE),
        metadata_plaintext_bytes,
        expected_sender_domain,
        circle_id,
        sidecar_id,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_local_mls_encrypt_for_event(
    mut state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    content_type: &str,
    event_kind: &str,
    plaintext_bytes: &[u8],
    metadata_content_type: Option<&str>,
    metadata_plaintext_bytes: Option<&[u8]>,
    expected_sender_domain: Option<&str>,
    circle_id: Option<&str>,
    sidecar_id: Option<&arkret_sdk::SidecarId>,
) -> Result<LocalMlsEncryptResult, crate::mls::runtime::MlsRuntimeError> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let realm_id_typed = arkret_sdk::RealmId::new(realm_id.to_owned()).map_err(|error| {
        crate::mls::runtime::MlsRuntimeError::Serialize(format!(
            "invalid Realm id for encrypted content: {error:?}"
        ))
    })?;
    let effective_scope = if let Some(sidecar_id) = sidecar_id {
        arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm_id_typed,
            sidecar_id: sidecar_id.clone(),
        }
    } else if let Some(circle_id) = circle_id {
        circle_effective_scope(realm_id, circle_id)
            .map_err(crate::mls::runtime::MlsRuntimeError::Serialize)?
    } else {
        arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id_typed,
        }
    };
    let snapshot = state_store
        .read()
        .mls_checkpoint_for_scope(&effective_scope)
        .ok_or(crate::mls::runtime::MlsRuntimeError::MissingWelcome)?;
    let group_state_ref = state_store
        .read()
        .mls_group_state_ref_for_scope(&effective_scope, &snapshot.group_id, snapshot.epoch)
        .map_err(|_| crate::mls::runtime::MlsRuntimeError::EncryptionTransitionPending)?;
    crate::mls::runtime::encrypt_message_with_device_snapshot(
        &mut state_store.write(),
        secure_store.as_ref(),
        realm_id,
        authority,
        device_id,
        content_type,
        event_kind,
        group_state_ref,
        plaintext_bytes,
        metadata_content_type,
        metadata_plaintext_bytes,
        expected_sender_domain,
        circle_id,
        sidecar_id,
    )
}

fn circle_effective_scope(
    realm_id: &str,
    circle_id: &str,
) -> Result<arkret_wire::ScopeRef, String> {
    Ok(arkret_wire::ScopeRef::Circle {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|error| format!("invalid MLS scope Realm id: {error:?}"))?,
        circle_id: arkret_sdk::CircleId::new(circle_id.to_owned())
            .map_err(|error| format!("invalid MLS scope Circle id: {error:?}"))?,
    })
}

/// Builds the encrypted write against an already accepted epoch reference.
pub(crate) type SecureMessagePlan = Box<
    dyn FnOnce(Option<&arkret_sdk::EventId>) -> Result<arkret_sdk::MessageAuthoringContent, String>
        + Send,
>;

/// A control Event this client authors and signs for itself.
pub(crate) type SecureControlPlan = Box<
    dyn FnOnce(Option<&arkret_sdk::EventId>) -> Result<crate::operation::LocalOperation, String>
        + Send,
>;

/// One ordinary message, ready to be completed by the account's own Station.
pub(crate) struct SecureMessageAuthoring {
    pub strand_id: String,
    pub reply_to: Option<String>,
    pub plan: SecureMessagePlan,
}

/// What the accepted MLS epoch is being used to write.
///
/// An ordinary message and a Sidecar control Event share encryption under an
/// accepted epoch, and nothing else: a message is completed by
/// the Station and only signed here, while a control Event is authored here.
/// Keeping both in one enum is what stops the message path from quietly growing
/// a second, locally authored way to send.
pub(crate) enum SecureWritePlan {
    Message(SecureMessageAuthoring),
    Control(SecureControlPlan),
}

pub(crate) struct SecureSendBuild {
    /// Freezes the encrypted write against the accepted epoch reference.
    pub message_plan: SecureWritePlan,
    /// Holder-local identity of the message this send will author.
    ///
    /// Allocated here so the optimistic bubble and its author-owned plaintext
    /// sidecar can be keyed before the Event — which waits on the commit's
    /// accepted id — exists.
    pub message_local_operation_id: crate::operation::LocalOperationId,
    /// Exact executable MLS scope used for snapshot/ref persistence.
    pub effective_scope: arkret_sdk::ScopeRef,
}

/// Build the full encrypted send (MLS encrypt →
/// `ak.schema.encrypted_envelope.v1` wrap → `ak.message.create` payload) for a
/// discussion message.
///
/// Honest fail-closed: returns `Err(msg)` whenever the MLS group cannot be
/// loaded / encrypted / committed for this Realm. The caller MUST surface the
/// message and abort — never fall back to a plaintext or fake send.
///
/// `metadata_plaintext_bytes` — optional `encrypted_metadata` plaintext (the
/// canonical `MessageMetadata` JSON, e.g. carrying
/// `message_metadata.sidecar_exchange_binding`). It is MLS-encrypted under the
/// same group/epoch and the same AAD/visibility as the content and mounted on
/// the message payload's `encrypted_metadata` field; it never enters plaintext
/// `metadata`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_secure_send(
    _api: &crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    _actor: &str,
    device_id: &arkret_sdk::DeviceId,
    strand_id: &str,
    local_message_id: &str,
    reply_to: Option<&str>,
    plaintext_bytes: &[u8],
    metadata_plaintext_bytes: Option<&[u8]>,
    circle_id: Option<&str>,
    sidecar_id: Option<arkret_sdk::SidecarId>,
) -> Result<SecureSendBuild, String> {
    if state_store
        .read()
        .realm_projection_has_retired_minimal_metadata_marker(realm_id)
    {
        return Err("retired minimal-metadata Realm marker cannot authorize MLS send".to_owned());
    }
    let typed_realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid MLS Realm id: {error}"))?;
    let effective_scope = if let Some(sidecar_id) = sidecar_id.as_ref() {
        arkret_sdk::ScopeRef::Sidecar {
            realm_id: typed_realm_id.clone(),
            sidecar_id: sidecar_id.clone(),
        }
    } else if let Some(circle_id) = circle_id {
        circle_effective_scope(realm_id, circle_id)?
    } else {
        arkret_sdk::ScopeRef::Realm {
            realm_id: typed_realm_id,
        }
    };
    crate::mls::creator_bootstrap::ensure_local_mls_transition_ready(
        &crate::app::runtime_adapter::state_store_handle(state_store),
        &effective_scope,
    )?;
    let encryption = run_local_mls_encrypt(
        state_store,
        realm_id,
        authority,
        device_id,
        plaintext_bytes,
        metadata_plaintext_bytes,
        None,
        circle_id,
        sidecar_id.as_ref(),
    )
    .map_err(|error| error.user_message())?;

    let encrypted_payload = encryption.content;
    let encrypted_metadata_message = encryption.metadata;
    if metadata_plaintext_bytes.is_some() && encrypted_metadata_message.is_none() {
        return Err("Send Secure could not produce the MLS encrypted metadata".to_owned());
    }
    if encryption.member_ids.is_empty() {
        return Err("Send Secure could not resolve MLS group members".to_owned());
    }

    let base_group_state_ref = state_store
        .read()
        .mls_group_state_ref_for_scope(
            &effective_scope,
            encrypted_payload.group_id.as_str(),
            encrypted_payload.epoch,
        )?
        .to_string();
    let plan_scope = effective_scope.clone();
    // The caller's optimistic row is already keyed by `local_message_id`; the
    // queue slot has to answer to that same key, or the row it belongs to can
    // never be found again.
    let message_local_operation_id =
        crate::operation::LocalOperationId::from_holder_key(local_message_id);
    let plan_local_operation_id = message_local_operation_id.clone();
    let message_plan: SecureMessagePlan = Box::new(move |_accepted_commit| {
        // Wrap the MLS payload in the spec-canonical
        // `ak.schema.encrypted_envelope.v1` wire shape, binding
        // key_ref.group_state_ref to the Event that established this epoch.
        let group_state_ref = arkret_sdk::EventId::new(base_group_state_ref)
            .map_err(|error| format!("invalid MLS group-state Event id: {error}"))?;
        if encrypted_payload.pre_encryption_header.group_state_ref != group_state_ref {
            return Err(
                "MLS encrypted payload group-state reference changed after sealing".to_owned(),
            );
        }
        // The frozen binding the ciphertext was sealed under. It travels with
        // the request so the Station can only complete an Event that reproduces
        // it: scheme, effective scope and sender domain are compared verbatim
        // before this device signs anything.
        let encryption_context = arkret_sdk::MessageEncryptionContext {
            scheme: encrypted_payload.pre_encryption_header.scheme.clone(),
            effective_scope: plan_scope,
            sender_domain: encrypted_payload
                .pre_encryption_header
                .sender_domain
                .clone(),
        };
        let encrypted_content =
            arkret_sdk::mls::encrypted_envelope_from_payload(&encrypted_payload)
                .map_err(|err| format!("MLS encrypted envelope build failed: {err}"))?;
        let encrypted_metadata = encrypted_metadata_message
            .as_ref()
            .map(|metadata_payload| {
                // Same canonical wrap + AAD visibility + group-state binding as
                // the `encrypted_content` envelope.
                arkret_sdk::mls::encrypted_envelope_from_payload(metadata_payload)
                    .map_err(|err| format!("MLS encrypted metadata envelope build failed: {err}"))
            })
            .transpose()?;
        let _ = &plan_local_operation_id;
        Ok(arkret_sdk::MessageAuthoringContent::Mls {
            encrypted_content,
            encrypted_metadata,
            encryption_context,
        })
    });

    Ok(SecureSendBuild {
        message_plan: SecureWritePlan::Message(SecureMessageAuthoring {
            strand_id: strand_id.to_owned(),
            reply_to: reply_to
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned),
            plan: message_plan,
        }),
        message_local_operation_id,
        effective_scope,
    })
}

/// Build the controller-authored durable close Event for a verified Sidecar
/// completion request. The control plaintext is MLS encrypted under the
/// native Sidecar MLS group and the outer Event carries `after` refs for every
/// basis head. A successful submit is still only an accepted control Event;
/// callers must wait for history refold before presenting the exchange as
/// closed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_sidecar_exchange_control_send(
    state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    actor: &str,
    device_id: &arkret_sdk::DeviceId,
    source_strand_id: &str,
    sidecar_id: arkret_sdk::SidecarId,
    control: &arkret_sdk::AgentSidecarExchangeControl,
) -> Result<SecureSendBuild, String> {
    control
        .validate_shape()
        .map_err(|error| format!("Sidecar exchange control validation failed: {error}"))?;
    let plaintext = serde_json::to_vec(control)
        .map_err(|error| format!("Sidecar exchange control encode failed: {error}"))?;
    let encryption = run_local_mls_encrypt_for_event(
        state_store,
        realm_id,
        authority,
        device_id,
        "application/vnd.arkret.agent-sidecar-exchange-control+json",
        arkret_sdk::EventKind::AgentSidecarExchangeControl.as_str(),
        &plaintext,
        None,
        None,
        None,
        None,
        Some(&sidecar_id),
    )
    .map_err(|error| error.user_message())?;
    let encrypted_payload = encryption.content;
    if encryption.metadata.is_some() || encryption.member_ids.is_empty() {
        return Err("Sidecar close produced an invalid MLS author result".to_owned());
    }
    let effective_scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|error| format!("Sidecar close Realm id invalid: {error}"))?,
        sidecar_id: sidecar_id.clone(),
    };
    let base_group_state_ref = state_store
        .read()
        .mls_group_state_ref_for_scope(
            &effective_scope,
            encrypted_payload.group_id.as_str(),
            encrypted_payload.epoch,
        )?
        .to_string();
    let source_strand_id = arkret_sdk::StrandId::new(source_strand_id.to_owned())
        .map_err(|error| format!("Sidecar close source Strand invalid: {error}"))?;
    let plan_sidecar_id = sidecar_id;
    let plan_refs: Vec<arkret_sdk::SemanticRef> = control
        .basis_event_ids
        .iter()
        .map(|event_id| arkret_sdk::SemanticRef::new(event_id.to_string(), "after"))
        .collect();
    let plan_realm_id = realm_id.to_owned();
    let plan_actor = actor.to_owned();
    let plan_scope = effective_scope.clone();
    let message_local_operation_id = crate::operation::LocalOperationId::new();
    let plan_local_operation_id = message_local_operation_id.clone();
    let message_plan: SecureControlPlan = Box::new(move |_accepted_commit| {
        let group_state_ref = arkret_sdk::EventId::new(base_group_state_ref)
            .map_err(|error| format!("invalid MLS group-state Event id: {error}"))?;
        if encrypted_payload.pre_encryption_header.group_state_ref != group_state_ref {
            return Err(
                "Sidecar close encrypted payload group-state reference changed after sealing"
                    .to_owned(),
            );
        }
        let encrypted_payload = arkret_sdk::mls::encrypted_envelope_from_payload(
            &encrypted_payload,
        )
        .map_err(|error| format!("Sidecar close encrypted envelope build failed: {error}"))?;
        let payload = arkret_sdk::AgentSidecarExchangeControlPayload {
            sidecar_id: plan_sidecar_id,
            source_context_ref: arkret_sdk::SidecarContextRef::Strand {
                strand_id: source_strand_id,
            },
            encrypted_payload,
        };
        crate::operation::TypedOperationBuilder::new::<
            arkret_sdk::event_spec::AgentSidecarExchangeControl,
        >(&plan_realm_id, &plan_actor, payload)
        .semantic_refs(plan_refs)
        .effective_scope(plan_scope)
        .build_sdk_event("inkson")
        .map(|operation| operation.with_local_operation_id(plan_local_operation_id))
        .map_err(|error| format!("Sidecar close SDK Event conversion failed: {error}"))
    });
    Ok(SecureSendBuild {
        message_plan: SecureWritePlan::Control(message_plan),
        message_local_operation_id,
        effective_scope,
    })
}

/// The result of submitting a [`SecureSendBuild`]: either the server-accepted
/// message event id or
/// a categorised failure the caller renders into its own UI.
pub(crate) enum SecureSendOutcome {
    /// Message accepted; `event_id` is the server's `ak.message.create` id.
    Sent { event_id: String, status: String },
    /// The `ak.message.create` submission failed (commit, if any, accepted).
    MessageFailed { message: String },
    /// The typed authoring engine refused or could not complete the message.
    ///
    /// This is a classified answer, not a message: the caller renders the exact
    /// reason and knows from [`garth::MessageAuthoringFailure::recovery`]
    /// whether anything is still in flight.
    MessageAuthoringFailed {
        failure: Box<garth::MessageAuthoringFailure>,
    },
}

/// Submit a built secure send after the same-epoch sender ratchet is durable.
///
/// The caller owns all UI reconciliation: it inspects [`SecureSendOutcome`] to
/// clear/fail the optimistic bubble, persist the author sidecar, restore the
/// draft, and emit any audit receipt.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn submit_secure_send(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    build: SecureSendBuild,
    realm_id: &str,
    circle_id: Option<String>,
) -> SecureSendOutcome {
    let SecureSendBuild {
        message_plan,
        message_local_operation_id,
        effective_scope,
    } = build;
    let sidecar_scope = matches!(&effective_scope, arkret_sdk::ScopeRef::Sidecar { .. });

    // `run_local_mls_encrypt` also advances the same-epoch send ratchet when
    // no commit is required. Freeze either path into the account-state writer
    // and await its IndexedDB barrier before the server can accept ciphertext
    // that a reload of this device would no longer be able to account for.
    let durable_state = match state_store.read().begin_durable_flush() {
        Ok(barrier) => barrier,
        Err(error) => {
            return SecureSendOutcome::MessageFailed {
                message: format!("begin durable MLS send-state persist: {error}"),
            };
        }
    };
    if let Err(error) = durable_state.wait().await {
        return SecureSendOutcome::MessageFailed {
            message: format!("durably persist MLS send state: {error}"),
        };
    }

    let control_event = match message_plan {
        SecureWritePlan::Message(authoring) => {
            let content = match (authoring.plan)(None) {
                Ok(content) => content,
                Err(message) => return SecureSendOutcome::MessageFailed { message },
            };
            return match crate::views::chat::model::send_ordinary_chat_message(
                api,
                realm_id,
                effective_scope,
                &authoring.strand_id,
                content,
                authoring.reply_to.as_deref(),
                message_local_operation_id.to_string(),
            )
            .await
            {
                Ok(resp) => SecureSendOutcome::Sent {
                    event_id: resp.event_id,
                    status: format!("{:?}", resp.status).to_ascii_lowercase(),
                },
                Err(failure) => {
                    // §2.4.1 `epoch_update_required`: record the receiver's
                    // coverage refusal so the per-Realm MLS effect advances the
                    // epoch instead of leaving the scope silently unsendable.
                    if !sidecar_scope
                        && matches!(
                            failure,
                            garth::MessageAuthoringFailure::EpochCommitPending { .. }
                        )
                    {
                        crate::mls::coverage_liveness::note_e2ee_epoch_update_required(
                            &crate::app::runtime_adapter::state_store_handle(state_store),
                            realm_id,
                            circle_id.as_deref(),
                            failure.detail(),
                        );
                    }
                    SecureSendOutcome::MessageAuthoringFailed {
                        failure: Box::new(failure),
                    }
                }
            };
        }
        SecureWritePlan::Control(plan) => match plan(None) {
            Ok(control_event) => control_event,
            Err(message) => return SecureSendOutcome::MessageFailed { message },
        },
    };
    match match api.event_submitter() {
        Ok(sub) => sub.submit_sdk_event(&control_event).await,
        Err(err) => Err(err),
    } {
        Ok(resp) => SecureSendOutcome::Sent {
            event_id: resp.event_id,
            status: format!("{:?}", resp.status).to_ascii_lowercase(),
        },
        // §2.4.1 `epoch_update_required`: record the receiver's coverage
        // refusal so the per-Realm MLS effect advances the epoch instead of
        // leaving the scope silently unsendable.
        Err(err)
            if !sidecar_scope
                && crate::mls::coverage_liveness::note_e2ee_submit_refusal(
                    &crate::app::runtime_adapter::state_store_handle(state_store),
                    realm_id,
                    circle_id.as_deref(),
                    &err,
                ) =>
        {
            SecureSendOutcome::MessageFailed {
                message: "Sending is paused until an MLS Commit covers the latest membership or \
                          key-access change; advancing the epoch"
                    .to_owned(),
            }
        }
        // Decision 0100 `epoch_mismatch`: a covering Commit already exists, so
        // nothing is repaired here. The frozen Event is never replayed; the
        // next attempt encrypts a new body once the current group is installed.
        Err(err)
            if crate::api_error::mls_send_refusal(&err)
                == Some(garth::MlsSendRefusal::EpochMismatch) =>
        {
            SecureSendOutcome::MessageFailed {
                message: "The MLS group moved to a newer epoch; refresh the group and send again \
                          to encrypt for the current epoch"
                    .to_owned(),
            }
        }
        Err(err) => SecureSendOutcome::MessageFailed {
            message: format!("Message send failed: {err}"),
        },
    }
}
