//! Converge locally executable MLS state from accepted durable Events.

use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

struct ExternalHistoryDecryptTask {
    realm_id: String,
    payload: arkret_sdk::EncryptedPayload,
    effective_scope: arkret_sdk::ScopeRef,
    binding_key: arkret_sdk::EventCandidateBindingKey,
}

#[derive(Clone)]
struct AcceptedCommit {
    event: arkret_sdk::Event,
    payload: arkret_sdk::MlsCommitPayload,
}

fn accepted_commits(
    state_store: &crate::state::LocalStateStore,
) -> Result<Vec<AcceptedCommit>, String> {
    let state = state_store.load();
    let mut by_event_id = std::collections::BTreeMap::new();
    for projection in state.realm_tree_projections.values() {
        let Some(events) = projection
            .get("state")
            .and_then(|state| state.get("events"))
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for event in events {
            let kind = event
                .get("kind")
                .or_else(|| event.get("event_kind"))
                .and_then(serde_json::Value::as_str);
            if kind != Some(arkret_wire::event_kind_str::MLS_COMMIT) {
                continue;
            }
            let event = serde_json::from_value::<arkret_sdk::Event>(event.clone())
                .map_err(|error| format!("accepted MLS Commit Event is invalid: {error}"))?;
            let payload = serde_json::from_value::<arkret_sdk::MlsCommitPayload>(
                serde_json::to_value(&event.payload).map_err(|error| error.to_string())?,
            )
            .map_err(|error| {
                format!("accepted MLS Commit {} is invalid: {error}", event.event_id)
            })?;
            let accepted = AcceptedCommit { event, payload };
            if let Some(existing) =
                by_event_id.insert(accepted.event.event_id.to_string(), accepted.clone())
                && existing.payload != accepted.payload
            {
                return Err("accepted MLS Commit changed under the same Event id".to_owned());
            }
        }
    }
    Ok(by_event_id.into_values().collect())
}

fn exact_next_commit(
    state_store: &crate::state::LocalStateStore,
    commits: &[AcceptedCommit],
) -> Result<Option<AcceptedCommit>, String> {
    let mut exact = Vec::new();
    let mut gaps = Vec::new();
    for accepted in commits {
        let scope = accepted.payload.governance_binding().effective_scope();
        let Some(snapshot) =
            state_store.mls_snapshot_for_scope_and_group(scope, accepted.payload.mls_group_id())
        else {
            continue;
        };
        if accepted.payload.next_epoch() <= snapshot.epoch {
            continue;
        }
        if accepted.payload.base_epoch() == snapshot.epoch {
            exact.push(accepted.clone());
        } else {
            gaps.push((scope.clone(), snapshot.epoch, accepted.payload.base_epoch()));
        }
    }
    exact.sort_by(|left, right| {
        left.payload
            .next_epoch()
            .cmp(&right.payload.next_epoch())
            .then_with(|| {
                left.event
                    .event_id
                    .as_str()
                    .cmp(right.event.event_id.as_str())
            })
    });
    if let Some(candidate) = exact.first() {
        let scope = candidate.payload.governance_binding().effective_scope();
        let forks = exact
            .iter()
            .filter(|other| {
                other.payload.mls_group_id() == candidate.payload.mls_group_id()
                    && other.payload.base_epoch() == candidate.payload.base_epoch()
                    && other.payload.governance_binding().effective_scope() == scope
            })
            .count();
        if forks > 1 {
            return Err(format!(
                "multiple accepted MLS Commits compete for group {} epoch {}",
                candidate.payload.mls_group_id(),
                candidate.payload.next_epoch()
            ));
        }
        return Ok(Some(candidate.clone()));
    }
    if let Some((scope, local_epoch, next_available_base)) = gaps.first() {
        return Err(format!(
            "accepted MLS Commit history has a gap for {scope:?}: local epoch {local_epoch}, next available base epoch {next_available_base}"
        ));
    }
    Ok(None)
}

/// Apply every locally reachable accepted winning Commit in strict epoch order.
///
/// Each entered epoch is exported to an encrypted snapshot and durably flushed
/// before the next Commit is considered. A missing by-reference proposal,
/// missing epoch, stale governance proof, or competing winner leaves the scope
/// pending and unsendable instead of skipping ahead.
pub(crate) async fn converge_accepted_mls_commits(
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
) -> Result<usize, String> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let snapshot_secret =
        super::load_device_snapshot_secret(secure_store.as_ref(), authority, device_id)
            .map_err(|error| format!("accepted Commit snapshot secret: {error}"))?;
    let mut applied = 0;
    loop {
        let commits = accepted_commits(&state_store.read())?;
        let Some(accepted) = exact_next_commit(&state_store.read(), &commits)? else {
            return Ok(applied);
        };
        let binding = accepted.payload.governance_binding().clone();
        let scope = binding.effective_scope().clone();
        let realm_id = scope
            .realm_id_opt()
            .ok_or_else(|| "accepted Commit has no executable Realm scope".to_owned())?
            .to_string();
        let canonical_group_id = scope
            .canonical_mls_group_id()
            .map_err(|error| format!("accepted Commit scope is invalid: {error}"))?;
        if canonical_group_id != accepted.payload.mls_group_id() {
            return Err("accepted Commit group id does not match its effective scope".to_owned());
        }
        let snapshot = state_store
            .read()
            .mls_snapshot_for_scope_and_group(&scope, accepted.payload.mls_group_id())
            .ok_or_else(|| "local MLS snapshot disappeared during convergence".to_owned())?;
        let base_ref = state_store.read().mls_group_state_ref_for_scope(
            &scope,
            accepted.payload.mls_group_id(),
            accepted.payload.base_epoch(),
        )?;
        if base_ref.as_str() != accepted.payload.base_epoch_ref() {
            return Err(format!(
                "accepted Commit base_epoch_ref {} does not match local accepted state {}",
                accepted.payload.base_epoch_ref(),
                base_ref
            ));
        }
        let verified = crate::mls::governance_proof::cached_verified_binding_for_transition(
            &state_store.read(),
            &scope,
            accepted.payload.mls_group_id(),
            accepted.payload.base_epoch(),
            accepted.payload.next_epoch(),
        )?;
        if verified != binding {
            return Err("accepted Commit governance binding is not locally verified".to_owned());
        }
        let mut group =
            crate::mls::persistence::restore_envelope(&snapshot, &snapshot_secret, 0)
                .map_err(|error| format!("restore accepted Commit base snapshot: {error}"))?;
        let content_scheme = match &scope {
            arkret_sdk::ScopeRef::Realm { .. } => {
                state_store.read().realm_content_scheme(&realm_id)
            }
            arkret_sdk::ScopeRef::Circle { circle_id, .. } => state_store
                .read()
                .circle_content_scheme(&realm_id, circle_id.as_str()),
            _ => None,
        };
        let history_capable = content_scheme
            .map(|scheme| scheme.trim().to_ascii_lowercase().replace('-', "_"))
            .is_some_and(|scheme| scheme == "mls_exporter_aead_v1");
        let envelope = accepted.payload.commit_envelope();
        if history_capable {
            group
                .apply_commit_and_retain_history_secret(&envelope, &realm_id)
                .map_err(|error| format!("apply accepted MLS Commit: {error}"))?;
        } else {
            group
                .apply_commit(&envelope)
                .map_err(|error| format!("apply accepted MLS Commit: {error}"))?;
        }
        if group
            .current_governance_binding()
            .map_err(|error| format!("{error:?}"))?
            != Some(binding)
        {
            return Err(
                "applied Commit GroupContext governance binding differs from the accepted Event"
                    .to_owned(),
            );
        }
        let post_state = group
            .export_state_record()
            .map_err(|error| format!("export accepted Commit snapshot: {error}"))?;
        let serialized = serde_json::to_vec(&post_state)
            .map_err(|error| format!("serialize accepted Commit snapshot: {error}"))?;
        let mut salt = [0_u8; 16];
        getrandom::fill(&mut salt)
            .map_err(|error| format!("generate accepted Commit snapshot salt: {error}"))?;
        let mut next_snapshot = crate::mls::persistence::encrypt_state(
            &realm_id,
            &post_state.group_id,
            post_state.epoch,
            &serialized,
            &snapshot_secret,
            &salt,
        );
        next_snapshot.group_state_event_id = Some(accepted.event.event_id.clone());

        let pending_history = if history_capable {
            let history_scope = arkret_sdk::HistoryEffectiveScope::try_from(scope.clone())
                .map_err(|error| format!("accepted Commit history scope: {error}"))?;
            let local_state_ref = format!(
                "inkson.mls_snapshot.v1:{}",
                arkret_sdk::canonical::canonical_sha256(&next_snapshot)
                    .map_err(|error| format!("digest accepted Commit snapshot: {error}"))?
            );
            let transition_event_digest = arkret_sdk::signed_event_digest_claim(&accepted.event)
                .map_err(|error| format!("accepted Commit Event digest: {error}"))?;
            let record = group
                .export_local_authoritative_history_secret(
                    &history_scope,
                    post_state.epoch,
                    &local_state_ref,
                    &accepted.event.event_id,
                    &transition_event_digest,
                    accepted.payload.commit_digest(),
                )
                .map_err(|error| format!("export accepted Commit history secret: {error}"))?;
            state_store
                .read()
                .prepare_history_secrets(
                    secure_store.as_ref(),
                    &scope,
                    &post_state.group_id,
                    [record],
                )
                .map_err(|error| format!("prepare accepted Commit history secret: {error}"))?
        } else {
            None
        };
        if let Some(pending) = pending_history.as_ref() {
            pending
                .persist(secure_store.as_ref())
                .await
                .map_err(|error| format!("persist accepted Commit history secret: {error}"))?;
        }
        let barrier = {
            let mut store = state_store.write();
            store.record_mls_group_state_ref_for_scope(
                &scope,
                &post_state.group_id,
                post_state.epoch,
                accepted.event.event_id,
            )?;
            store.save_mls_snapshot_for_scope(&scope, next_snapshot)?;
            if let Some(pending) = pending_history {
                store.publish_history_secrets(pending);
            }
            store
                .begin_durable_flush()
                .map_err(|error| error.to_string())?
        };
        barrier
            .wait()
            .await
            .map_err(|error| format!("durably persist accepted Commit snapshot: {error}"))?;
        applied += 1;
    }
}

/// Open accepted exporter-AEAD Events with bounded external candidates and
/// durably bind every candidate outcome before publishing plaintext to reads.
pub(crate) fn converge_external_history_candidate_decryptions(
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    actor_id: &str,
    device_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<usize, String> {
    let tasks = {
        let store = state_store.read();
        let state = store.load();
        let mut tasks = Vec::new();
        for projection in state.realm_tree_projections.values() {
            let Some(events) = projection
                .get("state")
                .and_then(|state| state.get("events"))
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for event in events {
                let Some(event_id) = event
                    .get("event_id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| arkret_sdk::EventId::new(value.to_owned()).ok())
                else {
                    continue;
                };
                let Some(effective_scope) = event
                    .get("scope_ref")
                    .or_else(|| event.get("effective_scope"))
                    .cloned()
                    .and_then(|value| serde_json::from_value::<arkret_sdk::ScopeRef>(value).ok())
                else {
                    continue;
                };
                let Some(realm_id) = effective_scope
                    .realm_id_opt()
                    .map(|realm_id| realm_id.as_str().to_owned())
                else {
                    continue;
                };
                let encrypted = event
                    .pointer("/payload/content/encrypted_content")
                    .or_else(|| event.pointer("/payload/encrypted_content"))
                    .or_else(|| event.pointer("/content/encrypted_content"))
                    .or_else(|| event.get("encrypted_content"));
                let Some(envelope) = encrypted.cloned().and_then(|value| {
                    serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(value).ok()
                }) else {
                    continue;
                };
                let Some(sender_domain) = crate::views::chat::verified_chat_sender_domain_for_realm(
                    &realm_id,
                    event,
                    Some(&store),
                    Some((actor_id, device_id)),
                ) else {
                    continue;
                };
                let Some(event_kind) = event.get("kind").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let reaction_routing_window = if matches!(
                    event_kind,
                    arkret_wire::event_kind_str::REACTION_ADD
                        | arkret_wire::event_kind_str::REACTION_REMOVE
                ) {
                    let Some(created_at) = event
                        .get("created_at")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| value.parse::<chrono::DateTime<chrono::Utc>>().ok())
                    else {
                        continue;
                    };
                    Some(created_at.timestamp_millis().div_euclid(3_600_000) as u64)
                } else {
                    None
                };
                let Some(payload) = super::message::encrypted_payload_from_verified_event_context(
                    &store,
                    &envelope,
                    &effective_scope,
                    event_kind,
                    &sender_domain,
                    reaction_routing_window,
                ) else {
                    continue;
                };
                tasks.push(ExternalHistoryDecryptTask {
                    realm_id,
                    payload: payload.clone(),
                    effective_scope: effective_scope.clone(),
                    binding_key: arkret_sdk::EventCandidateBindingKey {
                        effective_scope: match effective_scope {
                            arkret_sdk::ScopeRef::Realm { realm_id } => {
                                arkret_sdk::HistoryEffectiveScope::Realm { realm_id }
                            }
                            arkret_sdk::ScopeRef::Circle {
                                realm_id,
                                circle_id,
                            } => arkret_sdk::HistoryEffectiveScope::Circle {
                                realm_id,
                                circle_id,
                            },
                            _ => continue,
                        },
                        mls_group_id: payload.group_id.clone(),
                        epoch: payload.epoch,
                        event_digest: event_id.identity_key().event_digest(),
                        event_id,
                        verified_sender_domain: String::from_utf8(sender_domain)
                            .map_err(|_| "verified sender domain is not UTF-8".to_owned())?,
                    },
                });
            }
        }
        tasks
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let mut opened = 0;
    for task in tasks {
        let plaintext = {
            let mut store = state_store.write();
            super::decrypt_external_history_candidates_for_event(
                &mut store,
                secure_store.as_ref(),
                &task.realm_id,
                &task.payload,
                &task.effective_scope,
                task.binding_key,
                now,
            )
            .map_err(|error| error.user_message())?
        };
        if let Some(plaintext) = plaintext {
            state_store.read().cache_external_history_plaintext(
                &task.realm_id,
                task.payload.payload_digest.as_str(),
                &plaintext,
            );
            opened += 1;
        }
    }
    Ok(opened)
}
