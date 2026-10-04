//! Shared private conversation structure over the standard SDK writers.

use super::*;

pub(super) fn metadata_title(
    store: &LocalStateStore,
    realm: &str,
    id: &str,
    envelope: Option<&arkret_sdk::EncryptedEnvelope>,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) -> String {
    let Some(envelope) = envelope else {
        return id.to_owned();
    };
    let Ok(digest) = envelope.payload_digest() else {
        return id.to_owned();
    };
    let path = format!("encrypted_metadata:{digest}");
    let local = store
        .private_plaintext_for(realm, id, &path)
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let opened = local.or_else(|| {
        let cipher = serde_json::to_value(envelope).ok()?;
        let snapshot = store.load();
        let event = snapshot.raw_operations.iter().find_map(|record| {
            let event = record.payload.get("event").unwrap_or(&record.payload);
            let body = event.get("payload")?;
            let target = body.get("target_ref").or_else(|| body.get("space_id"));
            let creation = event
                .get("event_id")
                .and_then(Value::as_str)
                .and_then(|event_id| arkret_sdk::EventId::new(event_id).ok())
                .is_some_and(|event_id| {
                    if id.starts_with("ak:strand:") {
                        arkret_sdk::StrandId::from_event_id(&event_id).as_str() == id
                    } else {
                        arkret_sdk::SpaceId::from_event_id(&event_id).as_str() == id
                    }
                });
            let candidate = body
                .pointer("/object/encrypted_metadata")
                .or_else(|| body.pointer("/patch/encrypted_metadata/value"));
            ((creation || target.and_then(Value::as_str) == Some(id)) && candidate == Some(&cipher))
                .then_some(event)
        })?;
        let sender = model::verified_chat_sender_domain_for_realm(
            realm,
            event,
            Some(store),
            Some((account, "", device)),
        )?;
        let signed: arkret_sdk::Event = serde_json::from_value(event.clone()).ok()?;
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: signed.realm_id.clone(),
        };
        let payload = crate::mls::runtime::encrypted_payload_from_verified_event_context(
            store,
            envelope,
            &scope,
            signed.kind.as_str(),
            &sender,
            None,
        )?;
        let secure = crate::secure_key_store::default_secure_key_store("inkson");
        let bytes =
            crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
                store,
                secure.as_ref(),
                realm,
                account,
                device,
                &payload,
                &scope,
                &sender,
            )?;
        if id.starts_with("ak:space:") {
            let metadata: arkret_sdk::SpaceMetadata = serde_json::from_slice(&bytes).ok()?;
            metadata.validate().ok()?;
            serde_json::to_value(metadata).ok()
        } else {
            let metadata: arkret_sdk::StrandMetadata = serde_json::from_slice(&bytes).ok()?;
            serde_json::to_value(metadata).ok()
        }
    });
    opened
        .and_then(|metadata| {
            metadata
                .get("title")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("Encrypted · {}", short_protocol_id(id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_write(action: &str) -> StructureWrite {
        let token = "ASOv-EoZPg5yuM1Pv__u1K8vD3Q9342GxwoWmkKwjqOn";
        let realm = arkret_sdk::RealmId::new(format!("ak:realm:{token}")).unwrap();
        let chat = arkret_sdk::StrandId::new(format!("ak:strand:{token}")).unwrap();
        let topic = arkret_sdk::SpaceId::new(format!("ak:space:{token}")).unwrap();
        let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let mut view = garth::direct_structure::DirectStructureView::default();
        let mut strand =
            arkret_sdk::Strand::discussion(chat.clone(), realm.clone(), "Chat", actor.clone());
        strand.topic = Some(arkret_sdk::StrandTopic {
            space_id: topic.clone(),
            rank: "a0".into(),
        });
        view.chats.insert(chat.clone(), strand);
        view.chat_state_digests.insert(
            chat.clone(),
            arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        );
        view.spaces.insert(
            topic.clone(),
            arkret_sdk::Space::new(topic.clone(), realm, "topic", "Topic", actor),
        );
        StructureWrite {
            action: action.into(),
            title: "Title".into(),
            chat: chat.to_string(),
            topic: topic.to_string(),
            topic_target: topic.to_string(),
            view,
        }
    }

    #[test]
    fn direct_structure_classifies_and_unsets_with_exact_current_cas() {
        let write = sample_write("place");
        let realm = write
            .view
            .chats
            .values()
            .next()
            .unwrap()
            .realm_id
            .to_string();
        let actor = "ak:did_core:web:alice.example";
        let builder = builder_for(&write, &realm, actor, None).unwrap();
        let intent = builder.intent().unwrap();
        assert_eq!(intent.kind(), &arkret_sdk::EventKind::StrandUpdate);
        let payload = intent
            .typed_payload::<arkret_sdk::event_spec::StrandUpdate>()
            .unwrap();
        assert_eq!(payload.target_ref.as_str(), write.chat);
        assert_eq!(
            payload.expected_state_digest.as_ref().unwrap(),
            write.view.chat_state_digests.values().next().unwrap()
        );
        assert_eq!(
            serde_json::to_value(&payload).unwrap()["patch"]["topic"]["value"]["space_id"],
            write.topic
        );
        let clear = StructureWrite {
            action: "unplace".into(),
            ..write
        };
        let clear_builder = builder_for(&clear, &realm, actor, None).unwrap();
        let clear = clear_builder.intent().unwrap();
        assert_eq!(clear.payload()["patch"]["topic"], json!({"$op":"unset"}));
        assert!(!clear.payload().contains_key("board_space_id"));
    }

    #[test]
    fn direct_structure_rejects_missing_current_and_preserves_topic_on_reorder() {
        let mut write = sample_write("place");
        let realm = write
            .view
            .chats
            .values()
            .next()
            .unwrap()
            .realm_id
            .to_string();
        let actor = "ak:did_core:web:alice.example";
        write.view.chat_state_digests.clear();
        assert!(builder_for(&write, &realm, actor, None).is_err());
        let write = StructureWrite {
            action: "reorder".into(),
            ..sample_write("place")
        };
        let builder = builder_for(&write, &realm, actor, None).unwrap();
        let payload = builder.intent().unwrap();
        assert_eq!(
            payload.payload()["patch"]["topic"]["value"]["space_id"],
            write.topic
        );
    }
}

#[derive(Clone)]
struct StructureWrite {
    action: String,
    title: String,
    chat: String,
    topic: String,
    topic_target: String,
    view: garth::direct_structure::DirectStructureView,
}

fn builder_for(
    write: &StructureWrite,
    realm: &str,
    actor: &str,
    encrypted: Option<arkret_sdk::EncryptedEnvelope>,
) -> anyhow::Result<crate::operation::TypedOperationBuilder> {
    use arkret_sdk::event_spec;

    use crate::operation::TypedOperationBuilder;
    let space_id = |id: &str| arkret_sdk::SpaceId::new(id).map_err(anyhow::Error::from);
    let chat_id = arkret_sdk::StrandId::new(&write.chat).ok();
    Ok(match write.action.as_str() {
        "new_chat" => {
            let mut object = arkret_sdk::StrandCreateObject::new(
                arkret_sdk::RealmId::new(realm)?,
                crate::mls_api_helpers::local_account_actor_id(actor)?,
            )
            .with_track("discussion", arkret_sdk::StrandTrack::discussion_primary());
            object.encrypted_metadata = encrypted;
            let at = object.created_at;
            TypedOperationBuilder::new::<event_spec::StrandCreate>(
                realm,
                actor,
                ak_ops::strand_create_payload(object)?,
            )
            .created_at(at)
        }
        "new_topic" => {
            let mut space = arkret_sdk::Space::create_object(
                arkret_sdk::RealmId::new(realm)?,
                "topic",
                "",
                crate::mls_api_helpers::local_account_actor_id(actor)?,
            );
            space.title = None;
            space.encrypted_metadata = encrypted;
            let at = space.created_at;
            TypedOperationBuilder::new::<event_spec::SpaceCreate>(
                realm,
                actor,
                arkret_sdk::SpaceCreatePayload::new(space),
            )
            .created_at(at)
        }
        "rename_chat" => ak_ops::strand_update_patch(
            realm,
            actor,
            &write.chat,
            json!({"encrypted_metadata":{"$op":"set","value":encrypted}}),
        )?,
        "reorder_topic" => {
            let id = space_id(&write.topic_target)?;
            anyhow::ensure!(write.view.spaces.contains_key(&id), "Select a Topic");
            let tail = write
                .view
                .spaces
                .iter()
                .filter(|(other, _)| *other != &id)
                .filter_map(|(_, s)| s.rank.as_deref())
                .max();
            let rank = arkret_sdk::rank_between(tail, None)?;
            ak_ops::space_update_patch(
                realm,
                actor,
                &write.topic_target,
                json!({"rank":{"$op":"set","value":rank}}),
            )?
        }
        "rename_topic_target" => ak_ops::space_update_patch(
            realm,
            actor,
            &write.topic_target,
            json!({"encrypted_metadata":{"$op":"set","value":encrypted}}),
        )?,
        "archive_chat" => ak_ops::strand_archive(realm, actor, &write.chat)?,
        "restore_chat" => ak_ops::strand_restore(realm, actor, &write.chat)?,
        "place" | "unplace" | "reorder" => {
            let chat = chat_id.ok_or_else(|| anyhow::anyhow!("Select a Chat"))?;
            let current = write
                .view
                .chats
                .get(&chat)
                .ok_or_else(|| anyhow::anyhow!("Chat current is unavailable"))?;
            let expected = write
                .view
                .chat_state_digests
                .get(&chat)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Chat current digest is unavailable"))?;
            let classification = if write.action == "unplace" {
                anyhow::ensure!(current.topic.is_some(), "This Chat is already unclassified");
                None
            } else {
                let topic = space_id(&write.topic)?;
                anyhow::ensure!(
                    write
                        .view
                        .spaces
                        .get(&topic)
                        .is_some_and(|s| s.state == Some(arkret_sdk::SpaceState::Active)),
                    "Select an active Topic"
                );
                if write.action == "reorder" {
                    anyhow::ensure!(
                        current.topic.as_ref().is_some_and(|p| p.space_id == topic),
                        "Reorder must retain the current Topic"
                    );
                }
                let tail = write
                    .view
                    .chats
                    .iter()
                    .filter_map(|(id, s)| {
                        s.topic
                            .as_ref()
                            .filter(|p| *id != chat && p.space_id == topic)
                            .map(|p| p.rank.as_str())
                    })
                    .max();
                Some(arkret_sdk::StrandTopic {
                    space_id: topic,
                    rank: arkret_sdk::rank_between(tail, None)?,
                })
            };
            let payload =
                arkret_sdk::StrandPatchPayload::for_topic(chat, classification, expected)?;
            TypedOperationBuilder::new::<event_spec::StrandUpdate>(realm, actor, payload)
                .target_ref(&write.chat)
        }
        "archive_topic_target" | "restore_topic_target" => {
            let payload = arkret_sdk::SpaceStateTransitionPayload {
                space_id: space_id(&write.topic_target)?,
                reason: None,
                effective_at: None,
            };
            if write.action == "archive_topic_target" {
                TypedOperationBuilder::new::<event_spec::SpaceArchive>(realm, actor, payload)
                    .target_ref(&write.topic_target)
            } else {
                TypedOperationBuilder::new::<event_spec::SpaceRestore>(realm, actor, payload)
                    .target_ref(&write.topic_target)
            }
        }
        "delete_topic_target" => TypedOperationBuilder::new::<event_spec::SpaceTombstone>(
            realm,
            actor,
            arkret_sdk::SpaceObjectTombstonePayload {
                space_id: space_id(&write.topic_target)?,
                reason: None,
                replacement_space_id: None,
                replacement_event_id: None,
                effective_at: None,
            },
        )
        .target_ref(&write.topic_target),
        _ => anyhow::bail!("Unknown structure action"),
    })
}

async fn submit_structure(
    write: StructureWrite,
    realm: String,
    base: String,
    token: String,
    account: arkret_sdk::AccountId,
    device: arkret_sdk::DeviceId,
    mut store: SyncSignal<LocalStateStore>,
) -> anyhow::Result<(crate::models::SubmitEventResult, Option<String>)> {
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    anyhow::ensure!(
        crate::secure_key_store::active_device_seed_scope()
            .is_some_and(|s| s.authority == account && s.device_id == device),
        "Structure write belongs to another account or device"
    );
    let actor = account.principal_id.as_str();
    let context = store
        .read()
        .direct_message_context(&realm, &arkret_sdk::ActorId::account(account.clone()))
        .ok_or_else(|| anyhow::anyhow!("Conversation authority is pending"))?;
    anyhow::ensure!(
        context.authority_source == arkret_wire::AuthoritySourceId::DirectConversationParticipantV1,
        "Shared structure requires a stable conversation binding"
    );
    let needs_metadata = matches!(
        write.action.as_str(),
        "new_chat" | "new_topic" | "rename_chat" | "rename_topic_target"
    );
    let state_store = crate::app::runtime_adapter::state_store_handle(store);
    if needs_metadata {
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(&realm)?,
        };
        let input = crate::mls::send_gate::MlsSendGateInput::capture(&state_store, &scope);
        let gate = crate::mls::send_gate::resolve_restorable_mls_send_gate(&input, &scope, &device)
            .await?;
        anyhow::ensure!(
            matches!(gate, crate::mls::send_gate::MlsSendGate::Encrypted(_)),
            "Conversation encryption is not ready"
        );
        fence.check()?;
    }
    let plaintext = if needs_metadata {
        anyhow::ensure!(!write.title.trim().is_empty(), "Enter a title");
        Some(
            if matches!(write.action.as_str(), "new_chat" | "rename_chat") {
                serde_json::to_value(arkret_sdk::StrandMetadata::with_title(write.title.trim()))?
            } else {
                let metadata = arkret_sdk::SpaceMetadata::title(write.title.trim());
                metadata.validate()?;
                serde_json::to_value(metadata)?
            },
        )
    } else {
        None
    };
    let kind = match write.action.as_str() {
        "new_chat" => arkret_sdk::EventKind::StrandCreate,
        "rename_chat" => arkret_sdk::EventKind::StrandUpdate,
        "new_topic" => arkret_sdk::EventKind::SpaceCreate,
        _ => arkret_sdk::EventKind::SpaceUpdate,
    };
    let envelope = if let Some(plaintext) = &plaintext {
        let bytes = serde_json::to_vec(plaintext)?;
        let encryption = crate::views::secure_send::run_local_mls_encrypt_for_event(
            store,
            &realm,
            &account,
            &device,
            "application/json",
            kind.as_str(),
            &bytes,
            None,
            None,
            None,
            None,
            None,
        )
        .map_err(|error| anyhow::anyhow!(error.user_message()))?;
        Some(arkret_sdk::mls::encrypted_envelope_from_payload(
            &encryption.content,
        )?)
    } else {
        None
    };
    let draft = builder_for(&write, &realm, actor, envelope.clone())?;
    let intent = crate::mls::direct_binding::participant_authoring_intent(
        draft.intent()?,
        context.authority_source,
        &context.authority_event_ref,
    )?;
    let operation = crate::operation::LocalOperation::new(intent);
    let barrier = store.read().begin_durable_flush()?;
    barrier.wait().await?;
    fence.check()?;
    let api = authed_api_with_sync(&base, token, None)?;
    let accepted = api
        .event_submitter()?
        .with_state_store(state_store)
        .with_authority(account.clone())
        .submit_sdk_event(&operation)
        .await?;
    fence.check()?;
    let event_id = arkret_sdk::EventId::new(&accepted.event_id)?;
    let created_chat = (write.action == "new_chat")
        .then(|| arkret_sdk::StrandId::from_event_id(&event_id).to_string());
    if let (Some(envelope), Some(plaintext)) = (envelope, plaintext) {
        let id = match write.action.as_str() {
            "new_chat" => created_chat.clone().unwrap(),
            "new_topic" => arkret_sdk::SpaceId::from_event_id(&event_id).to_string(),
            "rename_chat" => write.chat,
            _ => write.topic_target,
        };
        store.write().save_private_plaintext(
            &realm,
            &id,
            &format!("encrypted_metadata:{}", envelope.payload_digest()?),
            &serde_json::to_string(&plaintext)?,
        );
        let barrier = store.read().begin_durable_flush()?;
        barrier.wait().await?;
    }
    Ok((accepted, created_chat))
}

#[component]
pub(super) fn DirectStructurePanel(
    realm: String,
    base: String,
    account: arkret_sdk::AccountId,
    device: arkret_sdk::DeviceId,
    token: Signal<String>,
    selected: Signal<String>,
    frontier: Signal<String>,
    live_epoch: Signal<u64>,
    on_select: EventHandler<String>,
) -> Element {
    let store = crate::app::SessionContext::get().state_store;
    let mut expanded = use_signal(|| false);
    let mut action = use_signal(|| "new_chat".to_owned());
    let mut title = use_signal(String::new);
    let mut topic = use_signal(String::new);
    let mut topic_target = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut pending = use_signal(|| false);
    let mut main = use_signal(|| None::<String>);
    let scope_key = format!("{}|{}|{}", realm, account, device);
    let mut active_scope = use_signal(|| scope_key.clone());
    use_effect(use_reactive((&scope_key,), move |(scope_key,)| {
        active_scope.set(scope_key);
        main.set(None);
        pending.set(false);
        status.set(String::new());
    }));
    let _epoch = live_epoch();
    let scope = arkret_sdk::RealmId::new(&realm)
        .ok()
        .map(|realm_id| arkret_sdk::ScopeRef::Realm { realm_id });
    let encryption_ready = matches!(
        crate::views::secure_send::use_scope_send_gate(store, scope, device.clone()),
        Some(crate::mls::send_gate::MlsSendGate::Encrypted(_))
    );
    let metadata_action = matches!(
        action().as_str(),
        "new_chat" | "new_topic" | "rename_chat" | "rename_topic_target"
    );
    let actor = arkret_sdk::ActorId::account(account.clone());
    let context = store.read().direct_message_context(&realm, &actor);
    let stable = context.as_ref().is_some_and(|c| {
        c.authority_source == arkret_wire::AuthoritySourceId::DirectConversationParticipantV1
    });
    let binding = context
        .map(|c| c.authority_event_ref.to_string())
        .unwrap_or_default();
    use_effect(use_reactive(
        (&realm, &base, &account, &binding),
        move |(realm, base, account, binding)| {
            if binding.is_empty() {
                main.set(None);
                return;
            }
            let peer = store.read().direct_conversation_peer(&realm);
            let Some(peer) = peer else {
                return;
            };
            let query_scope = active_scope();
            spawn(async move {
                let result = crate::transport::auth::with_authed_sdk_client(&base, token(), |http| async move {
                let outcome = http.direct_conversation_resolve(&arkret_sdk::direct_conversation::DirectConversationResolveRequestBody { peer }).await?;
                Ok(outcome.coordinates().filter(|c| c.realm_id.as_str() == realm).map(|c| c.main_strand_id.to_string()))
            }).await;
                if active_scope() != query_scope {
                    return;
                }
                if let Ok(value) = result {
                    main.set(value);
                }
                let _ = account;
            });
        },
    ));
    let view = {
        let state = store.read();
        let entries = state
            .current_product_view()
            .and_then(|view| view.entries_for(&realm).map(<[_]>::to_vec));
        arkret_sdk::RealmId::new(&realm)
            .ok()
            .and_then(|id| {
                entries.and_then(|entries| {
                    garth::direct_structure::DirectStructureView::from_current(&id, &entries).ok()
                })
            })
            .unwrap_or_default()
    };
    let mut chat_rows = view
        .chats
        .iter()
        .map(|(id, chat)| {
            (
                id.to_string(),
                metadata_title(
                    &store.read(),
                    &realm,
                    id.as_str(),
                    chat.encrypted_metadata.as_ref(),
                    &account,
                    &device,
                ),
                chat.state.clone(),
                chat.topic.as_ref().map(|p| p.space_id.to_string()),
            )
        })
        .collect::<Vec<_>>();
    let unread = arkret_sdk::RealmId::new(&realm)
        .ok()
        .map(|realm_id| {
            store.read().direct_chat_unread_counts(
                &realm_id,
                &actor,
                &view.chats.keys().cloned().collect(),
            )
        })
        .unwrap_or_default();
    let mut spaces = view
        .spaces
        .iter()
        .map(|(id, space)| {
            (
                id.to_string(),
                metadata_title(
                    &store.read(),
                    &realm,
                    id.as_str(),
                    space.encrypted_metadata.as_ref(),
                    &account,
                    &device,
                ),
                space.kind.clone(),
                space.parent_space_id.as_ref().map(ToString::to_string),
            )
        })
        .collect::<Vec<_>>();
    spaces.sort_by(|a, b| {
        let rank = |id: &str| {
            arkret_sdk::SpaceId::new(id)
                .ok()
                .and_then(|id| view.spaces.get(&id))
                .and_then(|s| s.rank.as_deref())
        };
        rank(&a.0).cmp(&rank(&b.0)).then_with(|| a.0.cmp(&b.0))
    });
    chat_rows.sort_by(|a, b| {
        let rank = |id: &str| {
            arkret_sdk::StrandId::new(id)
                .ok()
                .and_then(|id| view.chats.get(&id))
                .and_then(|s| s.topic.as_ref())
                .map(|p| p.rank.as_str())
        };
        a.3.cmp(&b.3)
            .then_with(|| rank(&a.0).cmp(&rank(&b.0)))
            .then_with(|| a.0.cmp(&b.0))
    });
    let target_is_main = main().as_deref() == Some(selected().as_str());
    let disable_main = main().is_none()
        || (target_is_main && matches!(action().as_str(), "archive_chat" | "restore_chat"));
    rsx! {
        div { class: "discussion-direct-structure", "data-testid": "direct-structure",
            if chat_rows.len() > 1 {
                select { "aria-label": "Chat", value: selected(), onchange: move |e| on_select.call(e.value()),
                    for (id, name, state, classification) in &chat_rows {
                        option { value: "{id}",
                            "{name}"
                            if let Some(count) = unread.get(id) { " ({count} unread)" }
                            if *state == Some(arkret_sdk::ObjectState::Archived) { " (archived)" }
                            if let Some(topic_id) = classification {
                                " · {spaces.iter().find(|(id,_,_,_)| id == topic_id).map(|(_,name,_,_)| name.as_str()).unwrap_or(topic_id.as_str())}"
                            }
                        }
                    }
                }
            }
            button { onclick: move |_| expanded.set(!expanded()), "Manage chats and topics" }
            if expanded() {
                select { "aria-label": "Action", value: action(), onchange: move |e| action.set(e.value()),
                    option { value: "new_chat", "New Chat" }
                    option { value: "new_topic", "New Topic" }
                    option { value: "rename_chat", "Rename Chat" }
                    option { value: "archive_chat", "Archive Chat" }
                    option { value: "restore_chat", "Restore Chat" }
                    option { value: "place", "Move Chat to Topic" }
                    option { value: "unplace", "Remove Chat from Topic" }
                    option { value: "reorder", "Move Chat to end of Topic" }
                    option { value: "rename_topic_target", "Rename Topic" }
                    option { value: "reorder_topic", "Move Topic to end" }
                    option { value: "archive_topic_target", "Archive Topic" }
                    option { value: "restore_topic_target", "Restore Topic" }
                    option { value: "delete_topic_target", "Delete empty Topic" }
                }
                if matches!(action().as_str(), "new_chat" | "new_topic" | "rename_chat" | "rename_topic_target") {
                    input { "aria-label": "Title", placeholder: "Title", value: title(), oninput: move |e| title.set(e.value()) }
                }
                if matches!(action().as_str(), "place" | "reorder") {
                    select { "aria-label": "Topic", value: topic(), onchange: move |e| topic.set(e.value()),
                        option { value: "", "Select Topic" }
                        for (id, name, kind, parent) in &spaces {
                            if kind == "topic" && parent.is_none()
                                && arkret_sdk::SpaceId::new(id).ok().and_then(|id| view.spaces.get(&id)).is_some_and(|space| space.state.as_ref().is_none_or(|state| state == &arkret_sdk::SpaceState::Active))
                            { option { value: "{id}", "{name}" } }
                        }
                    }
                }
                if matches!(action().as_str(), "rename_topic_target" | "reorder_topic" | "archive_topic_target" | "restore_topic_target" | "delete_topic_target") {
                    select { "aria-label": "Topic", value: topic_target(), onchange: move |e| topic_target.set(e.value()),
                        option { value: "", "Select Topic" }
                        for (id, name, _, _) in &spaces { option { value: "{id}", "{name}" } }
                    }
                }
                button { disabled: !stable || pending() || disable_main || (metadata_action && !encryption_ready),
                    onclick: {
                        let view = view.clone(); let realm = realm.clone(); let base = base.clone();
                        let account = account.clone(); let device = device.clone();
                        move |_| {
                            let write = StructureWrite { action: action(), title: title(), chat: selected(), topic: topic(), topic_target: topic_target(), view: view.clone() };
                            let realm = realm.clone(); let base = base.clone(); let account = account.clone(); let device = device.clone();
                            let write_scope = active_scope();
                            pending.set(true); status.set("Saving".into());
                            spawn(async move {
                                let result = submit_structure(write, realm, base, token(), account, device, store).await;
                                if active_scope() != write_scope { return; }
                                match result {
                                    Ok((accepted, chat)) => {
                                        frontier.set(accepted.event_id); live_epoch.set(live_epoch().wrapping_add(1));
                                        if let Some(chat) = chat { on_select.call(chat); }
                                        status.set("Saved".into()); title.set(String::new());
                                    }
                                    Err(error) => status.set(format!("{error:#}")),
                                }
                                pending.set(false);
                            });
                        }
                    }, "Save"
                }
                p { role: "status", "{status}" }
            }
        }
    }
}
