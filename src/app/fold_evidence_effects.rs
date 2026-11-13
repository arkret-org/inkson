use std::rc::Rc;

use glory::Scope;

use crate::presentation::InksonContext;

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
const SIDECAR_FOLD_EVIDENCE_HOOK: &str = "__inkson_sidecar_fold_evidence_v1";

/// Read-only test-controller evidence. Production builds expose no JS hooks.
pub(super) fn install(scope: &Scope, context: Rc<InksonContext>) {
    #[cfg(not(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test")))]
    let _ = (scope, context);
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    install_test_hooks(scope, context);
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
fn install_test_hooks(scope: &Scope, context: Rc<InksonContext>) {
    use wasm_bindgen::prelude::Closure;
    let Some(window) = web_sys::window() else {
        return;
    };
    let principal_id = context.principal_id;
    let active_account = context.active_account;
    let session_generation = context.session_generation;
    let fold_context = context.clone();
    let hook = Closure::<dyn Fn(String) -> String>::new(move |source_realm_id: String| {
        if !fold_context.session_generation.is_alive() {
            return serde_json::json!({"error":"owner retired"}).to_string();
        }
        let Some(controller_principal_id) = principal_id.get_untracked() else {
            return serde_json::json!({"error":"no signed-in controller"}).to_string();
        };
        let Some(controller_account_id) = active_account
            .get_untracked()
            .map(|account| account.authority)
        else {
            return serde_json::json!({"error":"no signed-in controller account"}).to_string();
        };
        if controller_account_id.principal_id != controller_principal_id {
            return serde_json::json!({"error":"signed-in controller account changed"}).to_string();
        }
        fold_context.state_store.read(|store| {
            crate::sidecar::sidecar_fold_evidence_canonical_json(
                store,
                &controller_account_id,
                &source_realm_id,
            )
            .unwrap_or_else(|error| serde_json::json!({"error":error.to_string()}).to_string())
        })
    });
    let sender_scope = scope.downgrade();
    let sender_context = context.clone();
    let sender = Closure::<dyn Fn(String, String, bool) -> js_sys::Promise>::new(
        move |realm_text: String, strand_text: String, typing: bool| {
            let (reply, received) = tokio::sync::oneshot::channel();
            if let Some(scope) = sender_scope.upgrade() {
                let context = sender_context.clone();
                let state_store = context.state_store.clone();
                let account = active_account.get_untracked();
                let generation = session_generation.get_untracked();
                let api_token = context.token.get_untracked();
                if let Err(error) = crate::runtime_helpers::spawn_owned(&scope, async move {
                    let phase = std::cell::Cell::new("account");
                    let result: anyhow::Result<serde_json::Value> = async {
                            let account =
                                account.ok_or_else(|| anyhow::anyhow!("account absent"))?;
                            phase.set("authoring_fence");
                            let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
                            phase.set("scope");
                            let realm = arkret_sdk::RealmId::new(realm_text)?;
                            let strand = arkret_sdk::StrandId::new(strand_text)?;
                            let scope = arkret_sdk::ScopeRef::Realm {
                                realm_id: realm.clone(),
                            };
                            phase.set("material");
                            let material = state_store.read(|store| crate::signal::key_material_for_scope(store, realm.as_str(), None))?;
                            let store =
                                state_store.handle();
                            phase.set("session");
                            let session = store
                                .read(|store| store.session_grant())
                                .ok_or_else(|| anyhow::anyhow!("session absent"))?;
                            phase.set("session_scope");
                            anyhow::ensure!(
                                session.account_id == account.authority
                                    && session.device_id == account.device_id,
                                "session does not belong to the active Device"
                            );
                            phase.set("credential");
                            anyhow::ensure!(!api_token.is_empty(), "session credential absent");
                            let group_id = scope.canonical_mls_group_id()?;
                            let epoch = material.epoch;
                            phase.set("pre_dispatch_fence");
                            fence.check()?;
                            anyhow::ensure!(
                                session_generation.get_untracked() == generation
                                    && active_account.get_untracked().as_ref().is_some_and(
                                        |current| current.authority == account.authority
                                            && current.device_id == account.device_id
                                            && current.server_url == account.server_url
                                            && current.profile_id == account.profile_id
                                    ),
                                "session replaced"
                            );
                            let base_url = account.server_url.to_string();
                            let authority = account.authority.clone();
                            let device = account.device_id.clone();
                            phase.set("blocklist_freshness");
                            let payload = crate::signal::SignalPayload::Typing {
                                strand_id: strand,
                                typing,
                            };
                            store.read(|store| store.require_blocklist_signal_freshness(&payload))?;
                            phase.set("send");
                            let outcome = crate::transport::auth::with_event_submitter(
                                &base_url,
                                api_token,
                                |submitter| async move {
                                    submitter
                                        .send_scope_signal(
                                            scope,
                                            &authority,
                                            &device,
                                            &material,
                                            &payload,
                                            &store,
                                        )
                                        .await
                                },
                            )
                            .await
                            .map_err(|_| anyhow::anyhow!("Signal send failed"))?;
                            phase.set("post_dispatch_fence");
                            fence.check()?;
                            anyhow::ensure!(
                                session_generation.get_untracked() == generation
                                    && active_account.get_untracked().as_ref().is_some_and(
                                        |current| current.authority == account.authority
                                            && current.device_id == account.device_id
                                            && current.server_url == account.server_url
                                            && current.profile_id == account.profile_id
                                    ),
                                "session replaced"
                            );
                            Ok(serde_json::json!({"accepted": outcome.accepted,
                                "dispatched_recipient_count": outcome.dispatched_recipient_count,
                                "envelope_digest": outcome.envelope_digest,
                                "group_id": group_id, "epoch": epoch,
                                "sender_actor_id": arkret_sdk::ActorId::account(account.authority.clone()),
                                "sender_device_id": account.device_id}))
                        }
                        .await;
                    // Never return arbitrary transport errors or any body/key bytes.
                    let safe = result.unwrap_or_else(|_| {
                        serde_json::json!({"error": "real_signal_send_unavailable",
                            "failure_stage": phase.get()})
                    });
                    let _ = reply.send(safe.to_string());
                }) {
                    scope.report_error(error);
                }
            }
            wasm_bindgen_futures::future_to_promise(async move {
                let safe = received.await.unwrap_or_else(|_| {
                    serde_json::json!({"error":"real_signal_send_unavailable",
                        "failure_stage":"owner_retired"})
                    .to_string()
                });
                Ok(wasm_bindgen::JsValue::from_str(&safe))
            })
        },
    );
    let timeline_context = context.clone();
    let timeline =
        Closure::<dyn Fn(String, String) -> String>::new(move |realm: String, event: String| {
            if !timeline_context.session_generation.is_alive() {
                return serde_json::json!({"error":"owner_retired"}).to_string();
            }
            let Some(account) = timeline_context.active_account.get_untracked() else {
                return serde_json::json!({"error":"account_absent"}).to_string();
            };
            let Ok(realm) = arkret_sdk::RealmId::new(realm) else {
                return serde_json::json!({"error":"invalid_realm"}).to_string();
            };
            let event = if event.is_empty() {
                None
            } else {
                match arkret_sdk::EventId::new(event) {
                    Ok(event) => Some(event),
                    Err(_) => return serde_json::json!({"error":"invalid_event"}).to_string(),
                }
            };
            timeline_context.state_store.read(|store| {
                ordinary_timeline_evidence(
                    store,
                    &account.authority,
                    &account.device_id,
                    &realm,
                    event.as_ref(),
                )
                .to_string()
            })
        });
    let cut_scope = scope.downgrade();
    let cut_context = context.clone();
    let current_cut = Closure::<dyn Fn(String) -> js_sys::Promise>::new(move |realm: String| {
        let (reply, received) = tokio::sync::oneshot::channel();
        if let Some(scope) = cut_scope.upgrade() {
            let context = cut_context.clone();
            if let Err(error) = crate::runtime_helpers::spawn_owned(&scope, async move {
                let result: anyhow::Result<serde_json::Value> = async {
                    let realm = arkret_sdk::RealmId::new(realm)?;
                    let generation = context.session_generation.get_untracked();
                    let account = context.active_account.get_untracked();
                    let authority = account
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("account absent"))?
                        .authority
                        .clone();
                    let store = context.state_store.handle();
                    let location = store.read(|state| state.current_index_location());
                    let index = crate::state::current_index::CurrentIndex::open_existing_committed(
                        &authority,
                        location,
                        || {
                            anyhow::ensure!(
                                context.session_matches(generation, &account),
                                "session replaced"
                            );
                            store.read(|state| {
                                anyhow::ensure!(
                                    state.active_authority().as_ref() == Some(&authority)
                                        && !state.current_reset_required()
                                        && state.current_generation() > 0,
                                    "current index is not installed for this account"
                                );
                                Ok(state.current_generation())
                            })
                        },
                    )
                    .await?;
                    let heads = index.read_complete_cut_heads(&realm).await?;
                    anyhow::ensure!(
                        context.session_matches(generation, &account),
                        "session replaced"
                    );
                    Ok(serde_json::json!({"complete":heads.is_some(),
                        "heads":heads.unwrap_or_default()}))
                }
                .await;
                // Export only typed public coordinates, never storage contents
                // or arbitrary error messages. This observer performs no write.
                let safe =
                    result.unwrap_or_else(|_| serde_json::json!({"complete":false,"heads":[]}));
                let _ = reply.send(safe.to_string());
            }) {
                scope.report_error(error);
            }
        }
        wasm_bindgen_futures::future_to_promise(async move {
            Ok(wasm_bindgen::JsValue::from_str(
                &received.await.unwrap_or_else(|_| {
                    serde_json::json!({"complete":false,"heads":[]}).to_string()
                }),
            ))
        })
    });
    let receiver_context = context;
    let receiver = Closure::<dyn Fn(String) -> String>::new(move |command: String| {
        if !receiver_context.session_generation.is_alive() {
            return "[]".to_owned();
        }
        let Some(principal) = principal_id.get_untracked() else {
            return "[]".to_owned();
        };
        crate::signal_receive_engine::signal_receiver_evidence(
            principal.as_str(),
            command == "clear",
        )
    });
    for (name, function) in [
        (SIDECAR_FOLD_EVIDENCE_HOOK, hook.as_ref()),
        ("__inkson_signal_sender_evidence", sender.as_ref()),
        ("__inkson_signal_receiver_evidence", receiver.as_ref()),
        ("__inkson_ordinary_timeline_evidence", timeline.as_ref()),
        ("__inkson_durable_current_cut", current_cut.as_ref()),
    ] {
        if js_sys::Reflect::set(&window, &wasm_bindgen::JsValue::from_str(name), function).is_err()
        {
            tracing::warn!(name, "could not install controller evidence hook");
        }
    }
    // Keep closures alive exactly as long as the account owner. Do not leak
    // a process-global function that can access a retired account's store.
    if let Err(error) = scope.on_cleanup(move || {
        for (name, function) in [
            (SIDECAR_FOLD_EVIDENCE_HOOK, hook.as_ref()),
            ("__inkson_signal_sender_evidence", sender.as_ref()),
            ("__inkson_signal_receiver_evidence", receiver.as_ref()),
            ("__inkson_ordinary_timeline_evidence", timeline.as_ref()),
            ("__inkson_durable_current_cut", current_cut.as_ref()),
        ] {
            let key = wasm_bindgen::JsValue::from_str(name);
            if js_sys::Reflect::get(&window, &key).is_ok_and(|current| current == *function) {
                let _ = js_sys::Reflect::delete_property(window.as_ref(), &key);
            }
        }
    }) {
        scope.report_error(error);
    }
}

#[cfg(any(
    test,
    all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test")
))]
fn ordinary_timeline_evidence(
    store: &crate::state::LocalStateStore,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    realm: &arkret_sdk::RealmId,
    event: Option<&arkret_sdk::EventId>,
) -> serde_json::Value {
    use crate::identity::committed_sender::{
        ChatProofVerdict, verify_committed_chat_producer_proof,
    };
    use crate::state::projection::message_ops::{message_candidates, message_kind_is_create};
    if store.active_authority().as_ref() != Some(account) {
        return serde_json::json!({"error":"account_mismatch"});
    }
    let state = store.load();
    let mut count = 0;
    let mut exact = Vec::new();
    for record in &state.raw_operations {
        let candidates = message_candidates(&record.payload);
        if record.realm_id.as_deref() != Some(realm.as_str())
            || !candidates
                .iter()
                .any(|candidate| message_kind_is_create(candidate))
        {
            continue;
        }
        count += 1;
        if !event.is_some_and(|event| {
            candidates.iter().any(|candidate| {
                candidate
                    .get("event_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(event.as_str())
            })
        }) || exact.len() == 8
        {
            continue;
        }
        let proof = match verify_committed_chat_producer_proof(&record.payload) {
            ChatProofVerdict::Verified => "verified",
            ChatProofVerdict::Rejected => "rejected",
            ChatProofVerdict::Unresolved => "unresolved",
            ChatProofVerdict::Unattributed => "unattributed",
        };
        let strand = candidates
            .iter()
            .find_map(|candidate| {
                candidate
                    .get("strand_id")
                    .and_then(serde_json::Value::as_str)
            })
            .and_then(|value| arkret_sdk::StrandId::new(value.to_owned()).ok());
        let original = candidates.iter().find_map(|candidate| {
            serde_json::from_value::<arkret_sdk::Event>((*candidate).clone()).ok()
        });
        let envelope = original.as_ref().and_then(|original| {
            original
                .payload
                .get("encrypted_content")
                .cloned()
                .and_then(|value| {
                    serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(value).ok()
                })
        });
        let mut material = serde_json::json!({
            "original_decodes":original.is_some(), "encrypted_envelope_decodes":envelope.is_some(),
            "protected_original_retained":event.is_some_and(|event| store.encrypted_original(realm.as_str(), event).is_some()),
            "accepted_original_retained":state.verified_poll_inputs.iter().any(|input| event == Some(&input.event.event_id)),
        });
        if let (Some(original), Some(envelope)) = (&original, &envelope) {
            let secure = crate::secure_key_store::default_secure_key_store("inkson");
            let actor = arkret_sdk::ActorId::account(account.clone());
            let endpoint = arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
                device_id: device.clone(),
            };
            let vault = garth::mls::content_roots::ContentRootVault::new(
                secure.as_ref(),
                &actor,
                &endpoint,
            );
            let arkret_sdk::EncryptedEnvelopeEncryptionContext::EpochContent { root_ref, .. } =
                &envelope.encryption_context;
            let root = vault.cached_root(root_ref).ok().flatten();
            let public_epoch = root.as_ref().is_some_and(|root| {
                store
                    .historical_content_rosters
                    .material(account, original, envelope, &root.root_context)
                    .is_some()
            });
            let snapshot = store.mls_checkpoint_for_scope(&original.scope_ref);
            let epoch_reference =
                original
                    .scope_ref
                    .canonical_mls_group_id()
                    .ok()
                    .and_then(|group| {
                        store
                            .mls_group_state_ref_for_scope(
                                &original.scope_ref,
                                group.as_str(),
                                envelope.encryption_context.epoch(),
                            )
                            .ok()
                    });
            let sender = arkret_sdk::mls_basic_credential_identity(original.actual_signer()).ok();
            material["root_cached"] = root.is_some().into();
            material["public_epoch_ready"] = public_epoch.into();
            material["checkpoint_present"] = snapshot.is_some().into();
            material["checkpoint_epoch_matches"] = snapshot
                .is_some_and(|snapshot| snapshot.epoch == envelope.encryption_context.epoch())
                .into();
            material["epoch_reference_matches"] = epoch_reference
                .is_some_and(|reference| {
                    reference.as_str() == envelope.encryption_context.group_state_ref().as_str()
                })
                .into();
            let payload = sender.as_ref().and_then(|sender| {
                crate::mls::runtime::encrypted_payload_from_verified_original(
                    store,
                    secure.as_ref(),
                    account,
                    device,
                    original,
                    envelope,
                    sender,
                )
            });
            material["header_reconstructs"] = payload.is_some().into();
            material["aead_opens"] = payload
                .as_ref()
                .zip(root.as_ref())
                .is_some_and(|(payload, root)| {
                    arkret_crypto::content_history::open_content(
                        &root.root_base64url,
                        &payload.pre_encryption_header,
                        &payload.ciphertext,
                    )
                    .map(|plaintext| {
                        let _plaintext = zeroize::Zeroizing::new(plaintext);
                    })
                    .is_ok()
                })
                .into();
        }
        exact.push(serde_json::json!({
            "top_level_signed":record.payload.get("producer_proof").is_some_and(serde_json::Value::is_object),
            "nested_signed":record.payload.get("event").and_then(|value| value.get("producer_proof")).is_some_and(serde_json::Value::is_object),
            "proof_verdict":proof,"strand_id":strand,"material":material,
        }));
    }
    let stream = arkret_sdk::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let checkpoint = store.verified_commit_stream_cursor(&stream);
    serde_json::json!({
        "raw_message_count":count,
        "exact_records":exact,
        "verified_message_count":state.verified_message_commits.iter().filter(|row| row.accepted_ref.stream_ref.realm_id() == realm).count(),
        "exact_committed_count":state.verified_message_commits.iter().filter(|row| event == Some(&row.accepted_ref.event_id)).count(),
        "checkpoint_readable":checkpoint.is_ok(),
        "checkpoint_position":checkpoint.ok().flatten().map(|head| head.stream_position.to_string()),
    })
}

#[cfg(test)]
mod timeline_evidence_tests {
    use super::*;

    #[test]
    fn ordinary_history_evidence_is_read_only_and_contains_no_content_or_secrets() {
        let placeholder =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [31; 32]);
        let strand = arkret_sdk::StrandId::from_event_id(&placeholder);
        let (bundle, _, rows) = crate::test_support::committed_event::verified_realm_fixture_as(
            arkret_sdk::RealmId::from_event_id(&placeholder),
            vec![(
                "ak.message.create".into(),
                serde_json::json!({"strand_id":strand,"track_name":"discussion",
                "content":{"kind":"ak.content.text","body":"fixture-sensitive-content"}}),
            )],
            "alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        let account = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station("ak:did_core:web:station.example")
            .build();
        let directory = tempfile::tempdir().unwrap();
        let mut store =
            crate::state::LocalStateStore::with_path(directory.path().join("evidence.json"));
        store.switch_active_account(&account).unwrap();
        let event = &rows[0].event;
        store.upsert_raw_operation(event.event_id.to_string(), Some(bundle.realm_id.to_string()), serde_json::json!({
            "event":event,"event_id":event.event_id,"session_grant":"fixture-sensitive-grant","private_material":"fixture-sensitive-private-material"
        }));
        let before = store.load();
        let evidence = ordinary_timeline_evidence(
            &store,
            &account.authority,
            &account.device_id,
            &bundle.realm_id,
            Some(&event.event_id),
        );
        assert_eq!(evidence["raw_message_count"], 1);
        assert_eq!(evidence["exact_records"][0]["proof_verdict"], "verified");
        assert_eq!(evidence["exact_records"][0]["nested_signed"], true);
        let encoded = evidence.to_string();
        for private in [
            "fixture-sensitive-content",
            "fixture-sensitive-grant",
            "fixture-sensitive-private-material",
            "signature",
            "session_grant",
        ] {
            assert!(!encoded.contains(private));
        }
        assert_eq!(store.load(), before);
        let other = arkret_sdk::AccountId::new(
            "ak:did_core:web:bob.example".parse().unwrap(),
            account.authority.station_id.clone(),
        );
        assert_eq!(
            ordinary_timeline_evidence(
                &store,
                &other,
                &account.device_id,
                &bundle.realm_id,
                Some(&event.event_id)
            ),
            serde_json::json!({"error":"account_mismatch"})
        );
    }
}
