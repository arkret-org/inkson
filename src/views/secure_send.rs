//! Shared E2EE "Send Secure" pipeline.
//!
//! This module owns the MLS core + operation construction + commit/message
//! submission orchestration used by the Chat discussion view to send an
//! encrypted `ak.message.create`. It was extracted from the verified Chat
//! "Send Secure" strand so encryption, commit and persist-on-accept stay in one
//! path.
//!
//! Boundary: this module performs everything that MUST be identical across the
//! message-write path —
//!   1. MLS encrypt of the canonical Content Block bytes (`run_local_mls_encrypt` →
//!      `mls::runtime::encrypt_message_with_device_snapshot`),
//!   2. forced `ak.mls.commit` envelope build (governance binding / prev→post epoch /
//!      membership_frontier),
//!   3. spec-canonical `ak.schema.encrypted_envelope.v1` wrap bound to the group-state ref,
//!   4. `ak.message.create` payload build (with reply-to + message id),
//!   5. submission ordering — commit FIRST (persist-on-accept snapshot + §7.10 history-backup
//!      schedule + move-submission record), then message.
//!
//! UI-shaped concerns stay in the caller: the optimistic bubble, draft
//! recovery, author-owned sidecar persistence, and status
//! text. The caller drives these off the typed [`SecureSendBuild`] /
//! [`SecureSendOutcome`] returned here.

use dioxus::prelude::*;

use crate::state::{LocalSealView, LocalStateStore, MoveSubmissionState};

/// The structured MLS payload + the canonical AAD it was bound to.
pub(crate) type LocalEncryptedMessage = (
    arkret_sdk::EncryptedPayload,
    arkret_sdk::EncryptedEnvelopeAad,
);

/// Result of the local MLS encrypt step.
///
/// * `schedule_hash` — post-encrypt group key-schedule hash (B3d governance).
/// * `member_dids` — every principal DID in the group (membership sanity check).
/// * encrypted content — typed MLS payload + AAD, or `None` on failure.
/// * commit envelope — the SDK self-update commit, when the encrypt advanced the epoch (a forced
///   `ak.mls.commit` is then emitted).
/// * snapshot — post-commit snapshot, persisted by the caller ONLY after the server accepts the
///   `ak.mls.commit` (persist-on-accept).
pub(crate) type LocalMlsEncryptResult = (
    Option<arkret_sdk::Hash>,
    Vec<arkret_sdk::DidCoreId>,
    Option<LocalEncryptedMessage>,
    Option<LocalEncryptedMessage>,
    Option<crate::mls::runtime::PreparedMlsCommit>,
    Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    Option<crate::state::PendingHistorySecrets>,
    Option<Vec<u8>>,
);

/// Encrypt `plaintext_bytes` under the Realm MLS group and return the
/// structured MLS payload + the canonical AAD it was bound to, plus the
/// post-encrypt schedule hash, member DID set, optional self-update commit
/// envelope, and the post-commit snapshot to persist on accept.
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
    principal_id: &str,
    device_id: &str,
    plaintext_bytes: &[u8],
    metadata_plaintext_bytes: Option<&[u8]>,
    circle_id: Option<&str>,
    sidecar_binding: Option<&arkret_sdk::SidecarMlsBinding>,
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
        principal_id,
        device_id,
        arkret_sdk::MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE,
        arkret_sdk::EventKind::MessageCreate.as_str(),
        plaintext_bytes,
        metadata_plaintext_bytes.map(|_| arkret_sdk::MESSAGE_METADATA_MLS_CONTENT_TYPE),
        metadata_plaintext_bytes,
        circle_id,
        sidecar_binding,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_local_mls_encrypt_for_event(
    mut state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    principal_id: &str,
    device_id: &str,
    content_type: &str,
    event_kind: &str,
    plaintext_bytes: &[u8],
    metadata_content_type: Option<&str>,
    metadata_plaintext_bytes: Option<&[u8]>,
    circle_id: Option<&str>,
    sidecar_binding: Option<&arkret_sdk::SidecarMlsBinding>,
) -> Result<LocalMlsEncryptResult, crate::mls::runtime::MlsRuntimeError> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let aad_realm_id = arkret_sdk::RealmId::new(realm_id.to_owned()).map_err(|error| {
        crate::mls::runtime::MlsRuntimeError::Serialize(format!(
            "invalid Realm id for encrypted AAD: {error:?}"
        ))
    })?;
    let aad_scope = if let Some(binding) = sidecar_binding {
        arkret_sdk::ScopeRef::Sidecar {
            realm_id: aad_realm_id,
            sidecar_id: binding.sidecar_id.clone(),
        }
    } else if let Some(circle_id) = circle_id {
        circle_effective_scope(realm_id, circle_id)
            .map_err(crate::mls::runtime::MlsRuntimeError::Serialize)?
    } else {
        arkret_sdk::ScopeRef::Realm {
            realm_id: aad_realm_id,
        }
    };
    let aad =
        arkret_sdk::EncryptedEnvelopeAad::hidden(&aad_scope, event_kind).map_err(|error| {
            crate::mls::runtime::MlsRuntimeError::Serialize(format!(
                "invalid encrypted AAD scope: {error}"
            ))
        })?;
    let (
        schedule_hash,
        member_dids,
        payload,
        metadata_payload,
        commit_envelope,
        new_snapshot,
        pending_history_secrets,
        mention_routing_key,
    ) = crate::mls::runtime::encrypt_message_with_device_snapshot(
        &mut state_store.write(),
        secure_store.as_ref(),
        realm_id,
        principal_id,
        device_id,
        content_type,
        aad.clone(),
        plaintext_bytes,
        metadata_content_type,
        metadata_plaintext_bytes,
        circle_id,
        sidecar_binding,
    )?;
    Ok((
        Some(schedule_hash),
        member_dids,
        Some((payload, aad.clone())),
        metadata_payload.map(|payload| (payload, aad)),
        commit_envelope,
        new_snapshot,
        pending_history_secrets,
        mention_routing_key,
    ))
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

/// The built (but not yet submitted) secure-send artifacts: the optional
/// forced MLS commit event, the encrypted `ak.message.create` event, and
/// the metadata the caller needs to drive UI / persist-on-accept.
/// Builds the encrypted write once the epoch's group-state reference is known.
///
/// The encrypted envelope binds `key_ref.group_state_ref` to the Event that
/// established the epoch. When this send forces a commit, that Event is part of
/// the same send and has no identity until it is accepted — so the message is
/// built from the accepted commit id, never from a draft one.
/// `mention_sidecar_digest` is a producer-signed payload member, so the digests
/// travel in here rather than being written onto a built Event afterwards.
pub(crate) type SecureMessagePlan = Box<
    dyn FnOnce(
            Option<&arkret_sdk::EventId>,
            Vec<String>,
        ) -> Result<crate::operation::LocalOperation, String>
        + Send,
>;

pub(crate) struct SecureSendBuild {
    /// Forced `ak.mls.commit` to submit BEFORE the message, when the encrypt
    /// advanced the epoch. `None` rides the current epoch.
    pub commit_event: Option<crate::operation::LocalOperation>,
    /// Builds the encrypted write against the accepted epoch reference.
    pub message_plan: SecureMessagePlan,
    /// Holder-local identity of the message this send will author.
    ///
    /// Allocated here so the optimistic bubble and its author-owned plaintext
    /// sidecar can be keyed before the Event — which waits on the commit's
    /// accepted id — exists.
    pub message_local_operation_id: crate::operation::LocalOperationId,
    /// Post-commit snapshot — persisted by the caller ONLY after the server
    /// accepts the commit (persist-on-accept).
    pub new_mls_snapshot: Option<crate::mls::persistence::MlsSnapshotEnvelope>,
    /// The Realm move-seal ref captured at build time (covered-seals binding).
    pub seal_ref: String,
    /// History-secret update that must commit before either MLS event is sent.
    pub pending_history_secrets: Option<crate::state::PendingHistorySecrets>,
    /// `push-notifications.md` §4.5 mention routing key for the epoch the
    /// message was encrypted under. `None` whenever Realm policy forbids the
    /// sidecar, in which case the caller emits no `mention_sidecar_digest`.
    pub mention_routing_key: Option<Vec<u8>>,
    /// Exact executable MLS scope used for snapshot/ref persistence.
    pub effective_scope: arkret_sdk::ScopeRef,
}

/// Build the full encrypted send (MLS encrypt → forced commit event →
/// `ak.schema.encrypted_envelope.v1` wrap → `ak.message.create` payload) for a
/// discussion message.
///
/// Honest fail-closed: returns `Err(msg)` whenever the MLS group cannot be
/// loaded / encrypted / committed for this Realm. The caller MUST surface the
/// message and abort — never fall back to a plaintext or fake send.
///
/// `seal_view` is the caller-captured `seal_view_for_realm(realm_id)` snapshot;
/// passing it in keeps the (synchronous) `state_store` read at the call site.
/// `metadata_plaintext_bytes` — optional `encrypted_metadata` plaintext (the
/// canonical `MessageMetadata` JSON, e.g. carrying
/// `message_metadata.sidecar_exchange_binding`). It is MLS-encrypted under the
/// same group/epoch and the same AAD/visibility as the content and mounted on
/// the message payload's `encrypted_metadata` field; it never enters plaintext
/// `metadata`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_secure_send(
    state_store: SyncSignal<LocalStateStore>,
    seal_view: &LocalSealView,
    realm_id: &str,
    actor: &str,
    device_id: &str,
    strand_id: &str,
    local_message_id: &str,
    reply_to: Option<&str>,
    plaintext_bytes: &[u8],
    metadata_plaintext_bytes: Option<&[u8]>,
    circle_id: Option<&str>,
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<SecureSendBuild, String> {
    if state_store
        .read()
        .realm_projection_is_minimal_metadata(realm_id)
    {
        return Err(
            "minimal_metadata_pairwise_author_unavailable: authoring requires a Realm-scoped pairwise DidCoreId, its did:key proof DidFullId, and the exact accepted MLS LeafNode signing key"
                .to_owned(),
        );
    }
    let typed_realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid MLS Realm id: {error}"))?;
    let effective_scope = if let Some(binding) = sidecar_binding.as_ref() {
        arkret_sdk::ScopeRef::Sidecar {
            realm_id: typed_realm_id.clone(),
            sidecar_id: binding.sidecar_id.clone(),
        }
    } else if let Some(circle_id) = circle_id {
        circle_effective_scope(realm_id, circle_id)?
    } else {
        arkret_sdk::ScopeRef::Realm {
            realm_id: typed_realm_id,
        }
    };
    let seal_ref = seal_view.move_seal_ref();
    let (
        local_schedule_hash,
        local_member_dids,
        encrypted_message,
        encrypted_metadata_message,
        real_commit_envelope,
        new_mls_snapshot,
        pending_history_secrets,
        mention_routing_key,
    ): LocalMlsEncryptResult = run_local_mls_encrypt(
        state_store,
        realm_id,
        actor,
        device_id,
        plaintext_bytes,
        metadata_plaintext_bytes,
        circle_id,
        sidecar_binding.as_ref(),
    )
    .map_err(|error| error.user_message())?;

    let Some((encrypted_payload, envelope_aad)) = encrypted_message else {
        return Err("Send Secure could not produce an MLS encrypted payload".to_owned());
    };
    if metadata_plaintext_bytes.is_some() && encrypted_metadata_message.is_none() {
        return Err("Send Secure could not produce the MLS encrypted metadata".to_owned());
    }
    let Some(_local_schedule_hash) = local_schedule_hash else {
        return Err("Send Secure could not derive the MLS key schedule hash".to_owned());
    };
    if local_member_dids.is_empty() {
        return Err("Send Secure could not resolve MLS group members".to_owned());
    }

    let base_group_state_ref = state_store
        .read()
        .mls_group_state_ref_for_scope(
            &effective_scope,
            encrypted_payload.group_id.as_str(),
            encrypted_payload
                .epoch
                .saturating_sub(u64::from(real_commit_envelope.is_some())),
        )?
        .to_string();
    let commit_event = match real_commit_envelope.as_ref() {
        Some(prepared_commit) => Some(match sidecar_binding.as_ref() {
            Some(binding) => {
                crate::mls::group_events::mls_commit_event_from_store_for_sidecar_scope(
                    &state_store.read(),
                    realm_id,
                    actor,
                    &prepared_commit.envelope,
                    &prepared_commit.previous_governance_binding,
                    binding.clone(),
                )?
            }
            None => crate::mls::group_events::mls_commit_event_from_store_for_effective_scope(
                &state_store.read(),
                realm_id,
                circle_id,
                actor,
                &prepared_commit.envelope,
                &prepared_commit.previous_governance_binding,
            )?,
        }),
        None => None,
    };
    let typed_strand_id = arkret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|err| format!("Send Secure strand id invalid: {err:?}"))?;
    let plan_realm_id = realm_id.to_owned();
    let plan_actor = actor.to_owned();
    let plan_reply_to = reply_to
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned);
    let plan_scope = effective_scope.clone();
    // The caller's optimistic row is already keyed by `local_message_id`; the
    // queue slot has to answer to that same key, or the row it belongs to can
    // never be found again.
    let message_local_operation_id =
        crate::operation::LocalOperationId::from_holder_key(local_message_id);
    let plan_local_operation_id = message_local_operation_id.clone();
    let message_plan: SecureMessagePlan = Box::new(move |accepted_commit, mention_digests| {
        // Wrap the MLS payload in the spec-canonical
        // `ak.schema.encrypted_envelope.v1` wire shape, binding
        // key_ref.group_state_ref to the Event that established this epoch.
        let group_state_ref = match accepted_commit {
            Some(event_id) => event_id.to_string(),
            None => base_group_state_ref,
        };
        let encrypted_envelope = arkret_sdk::mls::encrypted_envelope_from_payload(
            &encrypted_payload,
            envelope_aad,
            arkret_sdk::EncryptedEnvelopeAadVisibility::Hidden,
            // `hidden` is at or below every possible Realm ceiling, so the
            // fail-closed `from_declared(None)` resolution always admits it. A
            // caller that starts emitting `routing_digest` MUST pass the Realm's
            // accepted `aad_visibility` component here instead.
            arkret_sdk::AadVisibilityCeiling::from_declared(None),
            &group_state_ref,
        )
        .map_err(|err| format!("MLS encrypted envelope build failed: {err}"))?;
        let encrypted_content =
            arkret_sdk::MlsEncryptedPayload::<arkret_sdk::ContentBlock>::new(encrypted_envelope)
                .map_err(|err| format!("MLS ContentBlock envelope type mismatch: {err}"))?;
        let mut message_payload = arkret_sdk::MessageCreatePayload::with_mls_encrypted_content(
            typed_strand_id,
            "discussion",
            encrypted_content,
        );
        if let Some((metadata_payload, metadata_aad)) = encrypted_metadata_message {
            // Same canonical wrap + AAD visibility + group-state binding as the
            // `encrypted_content` envelope, mounted parallel to it on the payload.
            let encrypted_metadata = arkret_sdk::mls::encrypted_envelope_from_payload(
                &metadata_payload,
                metadata_aad,
                arkret_sdk::EncryptedEnvelopeAadVisibility::Hidden,
                arkret_sdk::AadVisibilityCeiling::from_declared(None),
                &group_state_ref,
            )
            .map_err(|err| format!("MLS encrypted metadata envelope build failed: {err}"))?;
            let encrypted_metadata =
                arkret_sdk::MlsEncryptedPayload::<arkret_sdk::MessageMetadata>::new(
                    encrypted_metadata,
                )
                .map_err(|err| format!("MLS MessageMetadata envelope type mismatch: {err}"))?;
            message_payload = message_payload.with_mls_encrypted_metadata(encrypted_metadata);
        }
        if let Some(reply_to) = plan_reply_to {
            message_payload = message_payload.with_reply_to(reply_to);
        }
        // `event-payload.schema.json#/$defs/message_create_payload` puts
        // `mention_sidecar_digest` at the payload root and closes the object, so
        // nesting it under `content` would be a schema violation.
        message_payload.mention_sidecar_digest = mention_digests;
        crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageCreate>(
            &plan_realm_id,
            &plan_actor,
            message_payload,
        )
        .effective_scope(plan_scope)
        .build_sdk_event("inkson")
        .map(|operation| operation.with_local_operation_id(plan_local_operation_id))
        .map_err(|err| format!("Send Secure SDK Event conversion failed: {err}"))
    });

    Ok(SecureSendBuild {
        commit_event,
        message_plan,
        message_local_operation_id,
        new_mls_snapshot,
        seal_ref,
        pending_history_secrets,
        mention_routing_key,
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
pub(crate) fn build_sidecar_exchange_control_send(
    state_store: SyncSignal<LocalStateStore>,
    seal_view: &LocalSealView,
    realm_id: &str,
    actor: &str,
    device_id: &str,
    source_strand_id: &str,
    sidecar_binding: arkret_sdk::SidecarMlsBinding,
    control: &arkret_sdk::AgentSidecarExchangeControl,
) -> Result<SecureSendBuild, String> {
    control
        .validate()
        .map_err(|error| format!("Sidecar exchange control validation failed: {error}"))?;
    let plaintext = serde_json::to_vec(control)
        .map_err(|error| format!("Sidecar exchange control encode failed: {error}"))?;
    let (
        _,
        members,
        encrypted_control,
        encrypted_metadata,
        prepared_commit,
        new_mls_snapshot,
        pending_history_secrets,
        _,
    ) = run_local_mls_encrypt_for_event(
        state_store,
        realm_id,
        actor,
        device_id,
        "application/vnd.arkret.agent-sidecar-exchange-control+json",
        arkret_sdk::EventKind::AgentSidecarExchangeControl.as_str(),
        &plaintext,
        None,
        None,
        None,
        Some(&sidecar_binding),
    )
    .map_err(|error| error.user_message())?;
    let Some((encrypted_payload, envelope_aad)) = encrypted_control else {
        return Err("Sidecar close could not produce an MLS encrypted payload".to_owned());
    };
    if encrypted_metadata.is_some() || members.is_empty() {
        return Err("Sidecar close produced an invalid MLS author result".to_owned());
    }
    let effective_scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|error| format!("Sidecar close Realm id invalid: {error}"))?,
        sidecar_id: sidecar_binding.sidecar_id.clone(),
    };
    let base_group_state_ref = state_store
        .read()
        .mls_group_state_ref_for_scope(
            &effective_scope,
            encrypted_payload.group_id.as_str(),
            encrypted_payload
                .epoch
                .saturating_sub(u64::from(prepared_commit.is_some())),
        )?
        .to_string();
    let commit_event = match prepared_commit.as_ref() {
        Some(prepared) => Some(
            crate::mls::group_events::mls_commit_event_from_store_for_sidecar_scope(
                &state_store.read(),
                realm_id,
                actor,
                &prepared.envelope,
                &prepared.previous_governance_binding,
                sidecar_binding.clone(),
            )?,
        ),
        None => None,
    };
    let source_strand_id = arkret_sdk::StrandId::new(source_strand_id.to_owned())
        .map_err(|error| format!("Sidecar close source Strand invalid: {error}"))?;
    let plan_sidecar_id = sidecar_binding.sidecar_id;
    let plan_refs: Vec<arkret_sdk::EventRef> = control
        .basis_event_ids
        .iter()
        .map(|event_id| arkret_sdk::EventRef::new(event_id.to_string(), "after"))
        .collect();
    let plan_realm_id = realm_id.to_owned();
    let plan_actor = actor.to_owned();
    let plan_scope = effective_scope.clone();
    let message_local_operation_id = crate::operation::LocalOperationId::new();
    let plan_local_operation_id = message_local_operation_id.clone();
    let message_plan: SecureMessagePlan = Box::new(move |accepted_commit, _mention_digests| {
        let group_state_ref = match accepted_commit {
            Some(event_id) => event_id.to_string(),
            None => base_group_state_ref,
        };
        let encrypted_payload = arkret_sdk::mls::encrypted_envelope_from_payload(
            &encrypted_payload,
            envelope_aad,
            arkret_sdk::EncryptedEnvelopeAadVisibility::Hidden,
            arkret_sdk::AadVisibilityCeiling::from_declared(None),
            &group_state_ref,
        )
        .map_err(|error| format!("Sidecar close encrypted envelope build failed: {error}"))?;
        let payload = arkret_sdk::AgentSidecarExchangeControlPayload {
            sidecar_id: plan_sidecar_id,
            source_context_ref: arkret_sdk::sidecar_operations::SidecarContextRef::Strand {
                strand_id: source_strand_id,
            },
            encrypted_payload,
        };
        crate::operation::TypedOperationBuilder::new::<
            arkret_sdk::event_spec::AgentSidecarExchangeControl,
        >(&plan_realm_id, &plan_actor, payload)
        .refs(plan_refs)
        .effective_scope(plan_scope)
        .build_sdk_event("inkson")
        .map(|operation| operation.with_local_operation_id(plan_local_operation_id))
        .map_err(|error| format!("Sidecar close SDK Event conversion failed: {error}"))
    });
    Ok(SecureSendBuild {
        commit_event,
        message_plan,
        message_local_operation_id,
        new_mls_snapshot,
        seal_ref: seal_view.move_seal_ref(),
        pending_history_secrets,
        mention_routing_key: None,
        effective_scope,
    })
}

/// The result of submitting a [`SecureSendBuild`]: either the server-accepted
/// message event id (commit, if any, already accepted + snapshot persisted) or
/// a categorised failure the caller renders into its own UI.
pub(crate) enum SecureSendOutcome {
    /// Message accepted; `event_id` is the server's `ak.message.create` id.
    Sent { event_id: String, status: String },
    /// The forced MLS commit was rejected; message NOT submitted. Snapshot was
    /// NOT advanced (the next retry uses the correct `expected_prev_epoch`).
    CommitFailed { message: String },
    /// The `ak.message.create` submission failed (commit, if any, accepted).
    MessageFailed { message: String },
}

/// Submit a built secure send: forced `ak.mls.commit` first (persist-on-accept
/// snapshot + §7.10 history-backup schedule + move-submission record), then the
/// encrypted `ak.message.create`. The MLS core ordering + persistence here is
/// shared verbatim by the chat write path.
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
    mention_digests: Vec<String>,
) -> SecureSendOutcome {
    let SecureSendBuild {
        commit_event,
        message_plan,
        message_local_operation_id: _,
        new_mls_snapshot,
        seal_ref,
        pending_history_secrets,
        mention_routing_key: _,
        effective_scope,
    } = build;
    let sidecar_scope = matches!(&effective_scope, arkret_sdk::ScopeRef::Sidecar { .. });
    if let Some(pending) = pending_history_secrets {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        if let Err(error) = pending.persist(secure_store.as_ref()).await {
            return SecureSendOutcome::MessageFailed {
                message: format!("persist MLS history secret before send: {error}"),
            };
        }
        state_store.write().publish_history_secrets(pending);
    }
    let commit_op_id = commit_event
        .as_ref()
        .map(|commit| commit.local_operation_id().to_string());

    let mut accepted_commit_event_id = None::<arkret_sdk::EventId>;
    if let Some(commit_event) = commit_event {
        // Submit the forced MLS commit first; if it fails, abort the message
        // send (the Security Frontier will not bind). The message's
        // `group_state_ref` is this commit's ACCEPTED id, so it is also the
        // reason the message cannot be built before this point.
        match match api.event_submitter() {
            Ok(sub) => sub.submit_sdk_event(&commit_event).await,
            Err(err) => Err(err),
        } {
            Ok(resp) => {
                match arkret_sdk::EventId::new(resp.event_id.clone()) {
                    Ok(event_id) => accepted_commit_event_id = Some(event_id),
                    Err(error) => {
                        return SecureSendOutcome::MessageFailed {
                            message: format!(
                                "accepted MLS commit returned an invalid Event id: {error}"
                            ),
                        };
                    }
                }
                // X14 — persist-on-accept: the server accepted the commit, so
                // NOW advance the local snapshot to the post-commit epoch. On a
                // commit reject we skip this and the snapshot stays at the
                // pre-commit epoch, so the next Send Secure retries at the
                // correct `expected_prev_epoch` instead of skewing forever.
                if let Some(snapshot) = new_mls_snapshot {
                    let accepted_commit_ref = accepted_commit_event_id
                        .clone()
                        .expect("accepted commit id was captured above");
                    if let Err(error) = state_store.write().record_mls_group_state_ref_for_scope(
                        &effective_scope,
                        snapshot.group_id.as_str(),
                        snapshot.epoch,
                        accepted_commit_ref,
                    ) {
                        return SecureSendOutcome::MessageFailed {
                            message: format!("persist accepted MLS group-state reference: {error}"),
                        };
                    }
                    if let Err(error) = state_store
                        .write()
                        .save_mls_snapshot_for_scope(&effective_scope, snapshot)
                    {
                        return SecureSendOutcome::MessageFailed {
                            message: format!("persist accepted MLS snapshot: {error}"),
                        };
                    }
                }
                if let Some(commit_op_id) = commit_op_id {
                    state_store.write().record_move_submission_with_event_id(
                        commit_op_id,
                        Some(resp.event_id.clone()),
                        realm_id.to_owned(),
                        "mls_commit".to_owned(),
                        MoveSubmissionState::from_submit_state("accepted", None),
                        None,
                        Some(seal_ref.clone()),
                    );
                }
            }
            Err(err) => {
                return SecureSendOutcome::CommitFailed {
                    message: format!("MLS commit event submit failed: {err}"),
                };
            }
        }
    }

    let message_event = match message_plan(accepted_commit_event_id.as_ref(), mention_digests) {
        Ok(message_event) => message_event,
        Err(message) => return SecureSendOutcome::MessageFailed { message },
    };
    match match api.event_submitter() {
        Ok(sub) => sub.submit_sdk_event(&message_event).await,
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
                    &mut state_store,
                    realm_id,
                    circle_id.as_deref(),
                    &err,
                ) =>
        {
            SecureSendOutcome::MessageFailed {
                message: "Sending is paused until the MLS epoch covers the latest governance \
                          Seal; advancing the epoch"
                    .to_owned(),
            }
        }
        Err(err) => SecureSendOutcome::MessageFailed {
            message: format!("Message send failed: {err}"),
        },
    }
}
