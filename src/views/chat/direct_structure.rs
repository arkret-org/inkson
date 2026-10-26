//! Shared private conversation structure over the standard SDK writers.
use std::rc::Rc;

use glory::prelude::*;
use serde_json::{Value, json};

use crate::operation::ak_ops;
use crate::presentation::widgets::{empty, paragraph, reactive_distinct};
use crate::presentation::{InksonContext, View};
use crate::state::LocalStateStore;
use crate::transport::auth::authed_api_with_sync;
use crate::views::helpers::short_protocol_id;

fn owned_direct_agent(
    peer: &arkret_sdk::contact_operations::ContactPeer,
    account: &arkret_sdk::AccountId,
) -> Option<arkret_sdk::AccountId> {
    match peer {
        arkret_sdk::contact_operations::ContactPeer::Agent {
            actor_id,
            controller_account_id,
        } if controller_account_id == account => actor_id.as_account_id().cloned(),
        _ => None,
    }
}

pub(super) fn metadata_title(
    store: &LocalStateStore,
    realm: &str,
    id: &str,
    envelope: Option<&arkret_sdk::EncryptedEnvelope>,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) -> String {
    envelope
        .and_then(|envelope| {
            crate::identity::metadata::open_metadata(store, realm, id, envelope, account, device)
        })
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

    #[test]
    fn direct_reply_preference_requires_the_complete_controller_account() {
        let account = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let agent = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            account.station_id.clone(),
        );
        let peer = arkret_sdk::contact_operations::ContactPeer::Agent {
            actor_id: arkret_sdk::ActorId::account(agent.clone()),
            controller_account_id: account.clone(),
        };
        assert_eq!(owned_direct_agent(&peer, &account), Some(agent));
        let mut another_station = account.clone();
        another_station.station_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert_eq!(owned_direct_agent(&peer, &another_station), None);
        assert_eq!(
            owned_direct_agent(
                &arkret_sdk::contact_operations::ContactPeer::Human {
                    account_id: account.clone(),
                },
                &account
            ),
            None
        );
        assert_eq!(
            owned_direct_agent(
                &arkret_sdk::contact_operations::ContactPeer::Agent {
                    actor_id: arkret_sdk::ActorId::service(account.principal_id.clone()),
                    controller_account_id: account.clone(),
                },
                &account
            ),
            None
        );
    }

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
    store: crate::presentation::SharedStateStore,
) -> anyhow::Result<(crate::models::EventSubmissionProgress, Option<String>)> {
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    tracing::warn!(action = %write.action, stage = "starting", "Direct structure write diagnostic");
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    anyhow::ensure!(
        crate::secure_key_store::active_device_seed_scope()
            .is_some_and(|s| s.authority == account && s.device_id == device),
        "Structure write belongs to another account or device"
    );
    let actor = account.principal_id.as_str();
    let context = store
        .read(|value| {
            value.direct_structure_context(&realm, &arkret_sdk::ActorId::account(account.clone()))
        })
        .ok_or_else(|| anyhow::anyhow!("Conversation authority is pending"))?;
    anyhow::ensure!(
        context.authority_source == arkret_wire::AuthoritySourceId::DirectConversationParticipantV1,
        "Shared structure requires a stable conversation binding"
    );
    let needs_metadata = matches!(
        write.action.as_str(),
        "new_chat" | "new_topic" | "rename_chat" | "rename_topic_target"
    );
    let state_store = store.handle();
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
            &state_store,
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
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    tracing::warn!(action = %write.action, stage = "encrypted", "Direct structure write diagnostic");
    let draft = builder_for(&write, &realm, actor, envelope.clone())?;
    let intent = crate::mls::direct_binding::participant_authoring_intent(
        draft.intent()?,
        context.authority_source,
        &context.authority_event_ref,
    )?;
    let operation = crate::operation::LocalOperation::new(intent);
    let barrier = store.read(|value| value.begin_durable_flush())?;
    barrier.wait().await?;
    fence.check()?;
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    tracing::warn!(action = %write.action, stage = "durable", "Direct structure write diagnostic");
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
            "new_chat" => arkret_sdk::StrandId::from_event_id(&event_id).to_string(),
            "new_topic" => arkret_sdk::SpaceId::from_event_id(&event_id).to_string(),
            "rename_chat" => write.chat,
            _ => write.topic_target,
        };
        store.write(|value| -> anyhow::Result<_> {
            value.save_private_plaintext(
                &realm,
                &id,
                &format!("encrypted_metadata:{}", envelope.payload_digest()?),
                &serde_json::to_string(&plaintext)?,
            );
            Ok(())
        })?;
        let barrier = store.read(|value| value.begin_durable_flush())?;
        barrier.wait().await?;
    }
    Ok((accepted, created_chat))
}

const DIRECT_ACTIONS: [&str; 13] = [
    "new_chat",
    "new_topic",
    "rename_chat",
    "archive_chat",
    "restore_chat",
    "place",
    "unplace",
    "reorder",
    "rename_topic_target",
    "reorder_topic",
    "archive_topic_target",
    "restore_topic_target",
    "delete_topic_target",
];

fn direct_action_options(locale: crate::i18n::UiLocale) -> Vec<(String, String)> {
    DIRECT_ACTIONS
        .into_iter()
        .map(|value| {
            (
                value.to_owned(),
                crate::i18n::tr_for_locale(locale, &format!("chat.direct_structure.{value}")),
            )
        })
        .collect()
}

fn direct_chat_option_label(
    locale: crate::i18n::UiLocale,
    name: &str,
    unread: Option<&usize>,
    state: &Option<arkret_sdk::ObjectState>,
    topic: Option<&str>,
) -> String {
    let mut label = name.to_owned();
    if let Some(count) = unread {
        label.push_str(&crate::i18n::substitute_args(
            crate::i18n::tr_for_locale(locale, "chat.direct_structure.unread_suffix"),
            &[("count", count.to_string())],
        ));
    }
    if *state == Some(arkret_sdk::ObjectState::Archived) {
        label.push_str(&crate::i18n::tr_for_locale(
            locale,
            "chat.direct_structure.archived_suffix",
        ));
    }
    if let Some(topic) = topic {
        label.push_str(" · ");
        label.push_str(topic);
    }
    label
}

/// Protocol values can be longer than semantic keys. Keep the mapping explicit
/// and preserve the original values presented by the native HTML select.
fn structure_select(
    scope: &Scope,
    key: &str,
    label: impl Into<Lotus<String>>,
    selected: Cage<String>,
    options: Vec<(String, String)>,
    changed: Rc<dyn Fn(String)>,
) -> View {
    let label = label.into();
    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::presentation::native_choice::{
            NativeChoiceOption, NativeChoiceProps, native_choice,
        };
        let value = scope.bond(move || Some(selected.get()));
        native_choice(
            scope,
            NativeChoiceProps::new(
                key.to_owned(),
                label,
                value,
                options
                    .into_iter()
                    .map(|(value, label)| NativeChoiceOption::new(value, label))
                    .collect(),
                move |next| {
                    if let Some(value) = next {
                        changed(value);
                    }
                },
            )
            .class("select"),
        )
    }
    #[cfg(target_arch = "wasm32")]
    {
        web_structure_select(scope, key, label, selected, options, changed)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn web_structure_select(
    scope: &Scope,
    key: &str,
    label: impl Into<Lotus<String>>,
    selected: Cage<String>,
    options: Vec<(String, String)>,
    changed: Rc<dyn Fn(String)>,
) -> View {
    let options = Rc::new(options);
    let values = options.clone();
    let selected_key = scope.bond(move || {
        let current = selected.get();
        values
            .iter()
            .position(|(value, _)| *value == current)
            .map(|index| format!("opt-{index}"))
    });
    let entries = options
        .iter()
        .enumerate()
        .map(|(index, (value, label))| {
            sapid::select_option(format!("opt-{index}"), label.clone()).value(value.clone())
        })
        .collect::<Vec<_>>();
    Box::new(
        sapid::native_select(key)
            .unstyled()
            .label(label)
            .value(selected_key)
            .options(entries)
            .on_value_change(move |key| {
                if let Some(index) = key.and_then(|key| {
                    key.strip_prefix("opt-")
                        .and_then(|index| index.parse::<usize>().ok())
                }) && let Some((value, _)) = options.get(index)
                {
                    changed(value.clone());
                }
            }),
    )
}

async fn save_agent_reply(
    context: Rc<InksonContext>,
    realm: String,
    chat: String,
    account: arkret_sdk::AccountId,
    device: arkret_sdk::DeviceId,
    agent: arkret_sdk::AccountId,
    credential: String,
) -> anyhow::Result<()> {
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    anyhow::ensure!(
        crate::secure_key_store::active_device_seed_scope()
            .is_some_and(|scope| scope.authority == account && scope.device_id == device),
        "Reply preference belongs to another account or device"
    );
    let target = arkret_sdk::ParticipationScope::Strand {
        realm_id: arkret_sdk::RealmId::new(&realm)?,
        strand_id: arkret_sdk::StrandId::new(&chat)?,
    };
    let base = context.base_url.get_untracked();
    crate::transport::auth::with_authed_sdk_client(&base, credential, |http| async move {
        let existing = http
            .agent_participation_get(agent.principal_id.as_str())
            .await?;
        fence.check()?;
        let permitted = context.state_store.read(|state| {
            let direct = state
                .direct_message_context(&realm, &arkret_sdk::ActorId::account(account.clone()));
            direct.is_some_and(|direct| {
                direct.authority_source
                    == arkret_wire::AuthoritySourceId::DirectConversationParticipantV1
            }) && state
                .direct_conversation_peer(&realm)
                .as_ref()
                .and_then(|peer| owned_direct_agent(peer, &account))
                .as_ref()
                == Some(&agent)
        });
        anyhow::ensure!(permitted, "Direct Conversation ownership is pending");
        anyhow::ensure!(
            existing.agent_id == agent.principal_id.as_str(),
            "Participation belongs to another Agent"
        );
        let entry = existing
            .participation_entries
            .iter()
            .find(|entry| entry.target_scope == target);
        let mut selection = entry.map(|entry| entry.selection).unwrap_or_default();
        selection.message_creation_allowed = true;
        let request = arkret_sdk::ParticipationReplaceRequestBody {
            target_scope: target.clone(),
            selection,
            expected_version: entry.map(|entry| entry.version).unwrap_or(0),
        };
        let accepted = http
            .agent_participation_replace(agent.principal_id.as_str(), &request)
            .await?;
        fence.check()?;
        anyhow::ensure!(
            accepted.agent_id == agent.principal_id.as_str()
                && accepted
                    .participation_entries
                    .iter()
                    .any(|entry| entry.target_scope == target && entry.selection == selection),
            "Reply preference was not confirmed"
        );
        Ok(())
    })
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))
}

fn agent_reply_preference(
    scope: &Scope,
    context: Rc<InksonContext>,
    realm: String,
    chat: String,
    account: arkret_sdk::AccountId,
    device: arkret_sdk::DeviceId,
    agent: arkret_sdk::AccountId,
    token: Cage<String>,
    live_epoch: Cage<u64>,
) -> View {
    let pending = scope.cage(false);
    let status = scope.cage(String::new());
    let weak = scope.downgrade();
    let hint = context.translated(scope, "chat.direct_structure.reply_hint");
    let label = context.translated(scope, "chat.direct_structure.allow_agent_reply");
    Box::new(
        view().class("direct-agent-reply-preference").fill((
            paragraph("", hint),
            sapid::button()
                .unstyled()
                .label(label)
                .enabled(scope.bond(move || !pending.get()))
                .on_press(move || {
                    if pending.get_untracked() {
                        return;
                    }
                    let Some(scope) = weak.upgrade() else {
                        return;
                    };
                    {
                        let next_value = true;
                        pending.revise(|current| *current = next_value)
                    };
                    {
                        let next_value = "Saving reply preference…".into();
                        status.revise(|current| *current = next_value)
                    };
                    let realm = realm.clone();
                    let chat = chat.clone();
                    let account = account.clone();
                    let device = device.clone();
                    let agent = agent.clone();
                    let context = context.clone();
                    let generation = context.session_generation.get_untracked();
                    let accepted_account = context.active_account.get_untracked();
                    let credential = token.get_untracked();
                    if let Err(error) = scope.spawn(async move {
                        let result = save_agent_reply(
                            context.clone(),
                            realm,
                            chat,
                            account,
                            device,
                            agent,
                            credential,
                        )
                        .await;
                        if !context.session_matches(generation, &accepted_account) {
                            return;
                        }
                        match result {
                            Ok(()) => {
                                {
                                    let next_value = "Reply preference saved for this Chat".into();
                                    status.revise(|current| *current = next_value)
                                };
                                live_epoch.revise(|value| *value = value.wrapping_add(1));
                            }
                            Err(error) => {
                                let next_value = format!("{error:#}");
                                status.revise(|current| *current = next_value)
                            }
                        }
                        {
                            let next_value = false;
                            pending.revise(|current| *current = next_value)
                        };
                    }) {
                        {
                            let next_value = false;
                            pending.revise(|current| *current = next_value)
                        };
                        scope.report_error(error);
                    }
                }),
            view()
                .role(glory::render::Role::Status)
                .fill(text().kind(TextKind::Paragraph).content(status)),
        )),
    )
}

pub(super) struct DirectStructurePanelProps {
    pub realm: String,
    pub account: arkret_sdk::AccountId,
    pub device: arkret_sdk::DeviceId,
    pub token: Cage<String>,
    pub selected: Cage<String>,
    pub frontier: Cage<String>,
    pub live_epoch: Cage<u64>,
    pub on_select: Rc<dyn Fn(String)>,
}

pub(super) fn direct_structure_panel(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: DirectStructurePanelProps,
) -> View {
    let props = Rc::new(props);
    let expanded = scope.cage(false);
    let action = scope.cage("new_chat".to_owned());
    let title = scope.cage(String::new());
    let topic = scope.cage(String::new());
    let topic_target = scope.cage(String::new());
    let status = scope.cage(String::new());
    let pending = scope.cage(false);
    let main = scope.cage(None::<String>);
    let target = arkret_sdk::RealmId::new(&props.realm)
        .ok()
        .map(|realm_id| arkret_sdk::ScopeRef::Realm { realm_id });
    let probe = crate::views::secure_send::scope_send_probe(
        scope,
        context.clone(),
        target.into(),
        props.device.clone().into(),
    );
    let task_scope = scope.downgrade();
    let query_context = context.clone();
    let query_props = props.clone();
    let request = scope.cage(None::<(String, String)>);
    scope.effect(move || {
        let _=query_context.state_revision.get();
        let account=query_context.active_account.get();
        let credential=query_props.token.get();
        let binding=query_context.state_store.read(|store| store.direct_structure_context(&query_props.realm,&arkret_sdk::ActorId::account(query_props.account.clone())));
        let Some(binding)=binding.filter(|binding|binding.authority_source==arkret_wire::AuthoritySourceId::DirectConversationParticipantV1) else {
            if main.get_untracked().is_some() { { let next_value = None; main.revise(|current| *current = next_value) }; }
            if request.get_untracked().is_some() { { let next_value = None; request.revise(|current| *current = next_value) }; }
            return;
        };
        let key=(binding.authority_event_ref.to_string(),credential.clone());
        if request.get_untracked().as_ref()==Some(&key) { return; }
        let peer=query_context.state_store.read(|store| store.direct_conversation_peer(&query_props.realm));
        let Some(peer)=peer else { return; };
        let Some(scope)=task_scope.upgrade() else { return; };
        { let next_value = Some(key.clone()); request.revise(|current| *current = next_value) };
        let context=query_context.clone(); let realm=query_props.realm.clone();
        let generation=context.session_generation.get_untracked();
        let base=context.base_url.get_untracked();
        if let Err(error)=scope.spawn(async move {
            let result=crate::transport::auth::with_authed_sdk_client(&base,credential,|http|async move {
                let outcome=http.direct_conversation_resolve(&arkret_sdk::direct_conversation::DirectConversationResolveRequestBody {peer}).await?;
                Ok(outcome.coordinates().filter(|coordinates|coordinates.realm_id.as_str()==realm).map(|coordinates|coordinates.main_strand_id.to_string()))
            }).await;
            if !context.session_matches(generation,&account)||request.get_untracked().as_ref()!=Some(&key) { return; }
            if let Ok(value)=result && main.get_untracked()!=value {{ let next_value = value; main.revise(|current| *current = next_value) };}
        }) { scope.report_error(error); }
    });
    let reply_source = scope.bond({
        let context = context.clone();
        let props = props.clone();
        move || {
            let _ = context.state_revision.get();
            let agent = context.state_store.read(|store| {
                let binding = store.direct_structure_context(
                    &props.realm,
                    &arkret_sdk::ActorId::account(props.account.clone()),
                );
                binding
                    .filter(|binding| {
                        binding.authority_source
                            == arkret_wire::AuthoritySourceId::DirectConversationParticipantV1
                    })
                    .and_then(|_| store.direct_conversation_peer(&props.realm))
                    .as_ref()
                    .and_then(|peer| owned_direct_agent(peer, &props.account))
            });
            (agent, props.selected.get())
        }
    });
    let reply = reactive_distinct(reply_source, {
        let context = context.clone();
        let props = props.clone();
        move |scope, (agent, chat)| match agent {
            Some(agent) => agent_reply_preference(
                scope,
                context.clone(),
                props.realm.clone(),
                chat,
                props.account.clone(),
                props.device.clone(),
                agent,
                props.token,
                props.live_epoch,
            ),
            None => empty(),
        }
    });
    let command_scope = scope.downgrade();
    let source = scope.bond({
        let context = context.clone();
        let props = props.clone();
        move || {
            let _ = context.state_revision.get();
            let _ = props.live_epoch.get();
            (
                structure_projection_stamp(&context, &props),
                props.selected.get(),
                expanded.get(),
                action.get(),
                main.get(),
                context.locale.get(),
                probe.get().gate,
            )
        }
    });
    let controls = reactive_distinct(
        source,
        move |scope, (_, selected, is_expanded, chosen_action, main_chat, locale, gate)| {
            structure_surface(
                scope,
                command_scope.clone(),
                context.clone(),
                props.clone(),
                expanded,
                action,
                title,
                topic,
                topic_target,
                status,
                pending,
                selected,
                is_expanded,
                chosen_action,
                main_chat,
                locale,
                matches!(gate, Some(crate::mls::send_gate::MlsSendGate::Encrypted(_))),
            )
        },
    );
    Box::new(
        view()
            .class("discussion-direct-structure direct-structure")
            .fill((reply, controls)),
    )
}

#[allow(clippy::too_many_arguments)]
fn structure_surface(
    scope: &Scope,
    command_scope: glory::ui::WeakScope,
    context: Rc<InksonContext>,
    props: Rc<DirectStructurePanelProps>,
    expanded: Cage<bool>,
    action: Cage<String>,
    title: Cage<String>,
    topic: Cage<String>,
    topic_target: Cage<String>,
    status: Cage<String>,
    pending: Cage<bool>,
    selected: String,
    is_expanded: bool,
    chosen_action: String,
    main_chat: Option<String>,
    locale: crate::i18n::UiLocale,
    encryption_ready: bool,
) -> View {
    let realm = &props.realm;
    let actor = arkret_sdk::ActorId::account(props.account.clone());
    let store = &context.state_store;
    let binding = store.read(|store| store.direct_structure_context(realm, &actor));
    let stable = binding.as_ref().is_some_and(|binding| {
        binding.authority_source == arkret_wire::AuthoritySourceId::DirectConversationParticipantV1
    });
    let projection = store.read(|state| {
        let entries = state
            .current_product_view()
            .and_then(|projection| projection.entries_for(realm).map(<[_]>::to_vec));
        arkret_sdk::RealmId::new(realm)
            .ok()
            .and_then(|id| {
                entries.and_then(|entries| {
                    garth::direct_structure::DirectStructureView::from_current(&id, &entries).ok()
                })
            })
            .unwrap_or_default()
    });
    let mut chats = projection
        .chats
        .iter()
        .map(|(id, chat)| {
            (
                id.to_string(),
                store.read(|state| {
                    metadata_title(
                        state,
                        realm,
                        id.as_str(),
                        chat.encrypted_metadata.as_ref(),
                        &props.account,
                        &props.device,
                    )
                }),
                chat.state.clone(),
                chat.topic.as_ref().map(|topic| topic.space_id.to_string()),
            )
        })
        .collect::<Vec<_>>();
    let unread = arkret_sdk::RealmId::new(realm)
        .ok()
        .map(|realm| {
            store.read(|state| {
                state.direct_chat_unread_counts(
                    &realm,
                    &actor,
                    &projection.chats.keys().cloned().collect(),
                )
            })
        })
        .unwrap_or_default();
    let mut spaces = projection
        .spaces
        .iter()
        .map(|(id, space)| {
            (
                id.to_string(),
                store.read(|state| {
                    metadata_title(
                        state,
                        realm,
                        id.as_str(),
                        space.encrypted_metadata.as_ref(),
                        &props.account,
                        &props.device,
                    )
                }),
                space.kind.clone(),
                space.parent_space_id.as_ref().map(ToString::to_string),
            )
        })
        .collect::<Vec<_>>();
    spaces.sort_by(|a, b| {
        let rank = |id: &str| {
            arkret_sdk::SpaceId::new(id)
                .ok()
                .and_then(|id| projection.spaces.get(&id))
                .and_then(|space| space.rank.as_deref())
        };
        rank(&a.0).cmp(&rank(&b.0)).then_with(|| a.0.cmp(&b.0))
    });
    chats.sort_by(|a, b| {
        let rank = |id: &str| {
            arkret_sdk::StrandId::new(id)
                .ok()
                .and_then(|id| projection.chats.get(&id))
                .and_then(|chat| chat.topic.as_ref())
                .map(|topic| topic.rank.as_str())
        };
        a.3.cmp(&b.3)
            .then_with(|| rank(&a.0).cmp(&rank(&b.0)))
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut children = Vec::<View>::new();
    if chats.len() > 1 {
        let options = chats
            .iter()
            .map(|(id, name, state, classification)| {
                let topic = classification.as_ref().map(|topic| {
                    spaces
                        .iter()
                        .find(|(id, ..)| id == topic)
                        .map(|(_, name, ..)| name.as_str())
                        .unwrap_or(topic.as_str())
                });
                (
                    id.clone(),
                    direct_chat_option_label(locale, name, unread.get(id), state, topic),
                )
            })
            .collect();
        children.push(structure_select(
            scope,
            "direct-chat",
            context.translated(scope, "chat.direct_structure.chat"),
            props.selected,
            options,
            props.on_select.clone(),
        ));
    }
    children.push(Box::new(
        sapid::button()
            .unstyled()
            .label(context.translated(scope, "chat.direct_structure.manage"))
            .on_press(move || expanded.revise(|value| *value = !*value)),
    ));
    if is_expanded {
        children.push(structure_select(
            scope,
            "direct-action",
            context.translated(scope, "chat.direct_structure.action"),
            action,
            direct_action_options(locale),
            Rc::new(move |value| {
                let next_value = value;
                action.revise(|current| *current = next_value)
            }),
        ));
        let metadata_action = matches!(
            chosen_action.as_str(),
            "new_chat" | "new_topic" | "rename_chat" | "rename_topic_target"
        );
        if metadata_action {
            children.push(Box::new(
                sapid::field("direct-structure-title")
                    .unstyled()
                    .class(scope.bond(move || {
                        if title.get().is_empty() {
                            "direct-title-field".to_owned()
                        } else {
                            "direct-title-field has-value".to_owned()
                        }
                    }))
                    .label(context.translated(scope, "chat.label.title"))
                    .control(move |field| {
                        sapid::text_field()
                            .unstyled()
                            .field(field)
                            .value(title)
                            .on_value_change(move |value| title.revise(|current| *current = value))
                    }),
            ));
        }
        if matches!(chosen_action.as_str(), "place" | "reorder") {
            let options = std::iter::once((
                String::new(),
                crate::i18n::tr_for_locale(locale, "chat.direct_structure.select_topic"),
            ))
            .chain(
                spaces
                    .iter()
                    .filter(|(id, _, kind, parent)| {
                        kind == "topic"
                            && parent.is_none()
                            && arkret_sdk::SpaceId::new(id)
                                .ok()
                                .and_then(|id| projection.spaces.get(&id))
                                .is_some_and(|space| {
                                    space.state.as_ref().is_none_or(|state| {
                                        state == &arkret_sdk::SpaceState::Active
                                    })
                                })
                    })
                    .map(|(id, name, ..)| (id.clone(), name.clone())),
            )
            .collect();
            children.push(structure_select(
                scope,
                "direct-place-topic",
                context.translated(scope, "chat.direct_structure.topic"),
                topic,
                options,
                Rc::new(move |value| {
                    let next_value = value;
                    topic.revise(|current| *current = next_value)
                }),
            ));
        }
        if matches!(
            chosen_action.as_str(),
            "rename_topic_target"
                | "reorder_topic"
                | "archive_topic_target"
                | "restore_topic_target"
                | "delete_topic_target"
        ) {
            let options = std::iter::once((
                String::new(),
                crate::i18n::tr_for_locale(locale, "chat.direct_structure.select_topic"),
            ))
            .chain(
                spaces
                    .iter()
                    .map(|(id, name, ..)| (id.clone(), name.clone())),
            )
            .collect();
            children.push(structure_select(
                scope,
                "direct-target-topic",
                context.translated(scope, "chat.direct_structure.topic"),
                topic_target,
                options,
                Rc::new(move |value| {
                    let next_value = value;
                    topic_target.revise(|current| *current = next_value)
                }),
            ));
        }
        let disable_main = main_chat.is_none()
            || main_chat.as_deref() == Some(selected.as_str())
                && matches!(chosen_action.as_str(), "archive_chat" | "restore_chat");
        let weak = command_scope;
        let on_select = props.on_select.clone();
        let enabled = scope.bond(move || {
            stable && !pending.get() && !disable_main && (!metadata_action || encryption_ready)
        });
        children.push(Box::new(
            sapid::button()
                .unstyled()
                .label(context.translated(scope, "common.save"))
                .enabled(enabled)
                .on_press(move || {
                    if pending.get_untracked() || !enabled.get_untracked() {
                        return;
                    }
                    let Some(scope) = weak.upgrade() else {
                        return;
                    };
                    let write = StructureWrite {
                        action: action.get_untracked(),
                        title: title.get_untracked(),
                        chat: props.selected.get_untracked(),
                        topic: topic.get_untracked(),
                        topic_target: topic_target.get_untracked(),
                        view: projection.clone(),
                    };
                    let context = context.clone();
                    let props = props.clone();
                    let on_select = on_select.clone();
                    let generation = context.session_generation.get_untracked();
                    let account = context.active_account.get_untracked();
                    let base = context.base_url.get_untracked();
                    let credential = props.token.get_untracked();
                    let store = context.state_store.clone();
                    {
                        let next_value = true;
                        pending.revise(|current| *current = next_value)
                    };
                    {
                        let next_value = "Saving".into();
                        status.revise(|current| *current = next_value)
                    };
                    if let Err(error) = scope.spawn(async move {
                        let result = submit_structure(
                            write,
                            props.realm.clone(),
                            base,
                            credential,
                            props.account.clone(),
                            props.device.clone(),
                            store,
                        )
                        .await;
                        if !context.session_matches(generation, &account) {
                            return;
                        }
                        match result {
                            Ok((accepted, chat)) => {
                                {
                                    let next_value = accepted.event_id;
                                    props.frontier.revise(|current| *current = next_value)
                                };
                                props
                                    .live_epoch
                                    .revise(|value| *value = value.wrapping_add(1));
                                if let Some(chat) = chat {
                                    on_select(chat);
                                }
                                {
                                    let next_value = "Saved".into();
                                    status.revise(|current| *current = next_value)
                                };
                                {
                                    let next_value = String::new();
                                    title.revise(|current| *current = next_value)
                                };
                            }
                            Err(error) => {
                                let next_value = format!("{error:#}");
                                status.revise(|current| *current = next_value)
                            }
                        }
                        {
                            let next_value = false;
                            pending.revise(|current| *current = next_value)
                        };
                    }) {
                        {
                            let next_value = false;
                            pending.revise(|current| *current = next_value)
                        };
                        scope.report_error(error);
                    }
                }),
        ));
        children.push(Box::new(
            view()
                .role(glory::render::Role::Status)
                .class("direct-structure-status")
                .fill(text().kind(TextKind::Paragraph).content(status)),
        ));
    }
    Box::new(view().class("direct-structure-controls").fill(children))
}

fn structure_projection_stamp(
    context: &InksonContext,
    props: &DirectStructurePanelProps,
) -> String {
    context.state_store.read(|state| {
        let entries = state
            .current_product_view()
            .and_then(|view| view.entries_for(&props.realm).map(<[_]>::to_vec));
        let projection = arkret_sdk::RealmId::new(&props.realm)
            .ok()
            .and_then(|id| {
                entries.and_then(|entries| {
                    garth::direct_structure::DirectStructureView::from_current(&id, &entries).ok()
                })
            })
            .unwrap_or_default();
        let chats = projection
            .chats
            .iter()
            .map(|(id, chat)| {
                (
                    id.to_string(),
                    metadata_title(
                        state,
                        &props.realm,
                        id.as_str(),
                        chat.encrypted_metadata.as_ref(),
                        &props.account,
                        &props.device,
                    ),
                )
            })
            .collect::<Vec<_>>();
        let topics = projection
            .spaces
            .iter()
            .map(|(id, space)| {
                (
                    id.to_string(),
                    metadata_title(
                        state,
                        &props.realm,
                        id.as_str(),
                        space.encrypted_metadata.as_ref(),
                        &props.account,
                        &props.device,
                    ),
                )
            })
            .collect::<Vec<_>>();
        let actor = arkret_sdk::ActorId::account(props.account.clone());
        let unread = arkret_sdk::RealmId::new(&props.realm)
            .ok()
            .map(|realm| {
                state.direct_chat_unread_counts(
                    &realm,
                    &actor,
                    &projection.chats.keys().cloned().collect(),
                )
            })
            .unwrap_or_default();
        let binding = state
            .direct_structure_context(&props.realm, &actor)
            .map(|binding| {
                (
                    binding.authority_source
                        == arkret_wire::AuthoritySourceId::DirectConversationParticipantV1,
                    binding.authority_event_ref.to_string(),
                )
            });
        match serde_json::to_vec(&(
            projection.chats,
            projection.spaces,
            projection.chat_state_digests,
            chats,
            topics,
            unread,
            binding,
        )) {
            Ok(bytes) => arkret_sdk::canonical::sha256_hex(&bytes),
            Err(error) => format!("invalid-direct-projection:{error}"),
        }
    })
}

#[cfg(test)]
mod locale_tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;
    use crate::i18n::UiLocale;
    const RAW_TITLE: &str = "chat.direct_structure.new_chat {count} 原文";
    const RAW_TOPIC: &str = "chat.direct_structure.archived_suffix {topic} 原始话题";
    const ACTIONS: [&str; 13] = [
        "new_chat",
        "new_topic",
        "rename_chat",
        "archive_chat",
        "restore_chat",
        "place",
        "unplace",
        "reorder",
        "rename_topic_target",
        "reorder_topic",
        "archive_topic_target",
        "restore_topic_target",
        "delete_topic_target",
    ];
    const ENGLISH: [&str; 13] = [
        "New Chat",
        "New Topic",
        "Rename Chat",
        "Archive Chat",
        "Restore Chat",
        "Move Chat to Topic",
        "Remove Chat from Topic",
        "Move Chat to end of Topic",
        "Rename Topic",
        "Move Topic to end",
        "Archive Topic",
        "Restore Topic",
        "Delete empty Topic",
    ];
    const CHINESE: [&str; 13] = [
        "新建聊天",
        "新建话题",
        "重命名聊天",
        "归档聊天",
        "恢复聊天",
        "将聊天移入话题",
        "将聊天移出话题",
        "将聊天移到话题末尾",
        "重命名话题",
        "将话题移到末尾",
        "归档话题",
        "恢复话题",
        "删除空话题",
    ];

    #[derive(Default)]
    struct Handles {
        locale: Option<Cage<UiLocale>>,
        action: Option<Cage<String>>,
        title: Option<Cage<String>>,
        topic: Option<Cage<String>>,
        unread: Option<Cage<Option<usize>>>,
        state: Option<Cage<Option<arkret_sdk::ObjectState>>>,
        initializations: usize,
    }
    fn retained_direct_labels(scope: &Scope, handles: Rc<RefCell<Handles>>) -> View {
        let locale = scope.cage(UiLocale::En);
        let action = scope.cage({
            handles.borrow_mut().initializations += 1;
            "new_chat".to_owned()
        });
        let title = scope.cage({
            handles.borrow_mut().initializations += 1;
            RAW_TITLE.to_owned()
        });
        let topic = scope.cage({
            handles.borrow_mut().initializations += 1;
            RAW_TOPIC.to_owned()
        });
        let unread = scope.cage({
            handles.borrow_mut().initializations += 1;
            Some(7usize)
        });
        let state = scope.cage({
            handles.borrow_mut().initializations += 1;
            Some(arkret_sdk::ObjectState::Archived)
        });
        {
            let mut handle = handles.borrow_mut();
            handle.locale = Some(locale);
            handle.action = Some(action);
            handle.title = Some(title);
            handle.topic = Some(topic);
            handle.unread = Some(unread);
            handle.state = Some(state);
        }
        let selected = scope.cage("raw-chat".to_owned());
        let source = scope.bond(move || {
            (
                locale.get(),
                title.get(),
                topic.get(),
                unread.get(),
                state.get(),
            )
        });
        reactive_distinct(
            source,
            move |scope, (locale, title, topic, unread, state)| {
                Box::new(view().fill((
                    web_structure_select(
                        scope,
                        "test-direct-action",
                        crate::i18n::tr_for_locale(locale, "chat.direct_structure.action"),
                        action,
                        direct_action_options(locale),
                        Rc::new(move |next| {
                            let next_value = next;
                            action.revise(|current| *current = next_value)
                        }),
                    ),
                    web_structure_select(
                        scope,
                        "test-direct-labels",
                        "Chats",
                        selected,
                        vec![
                            (
                                "raw-chat".to_owned(),
                                direct_chat_option_label(
                                    locale,
                                    &title,
                                    unread.as_ref(),
                                    &state,
                                    Some(&topic),
                                ),
                            ),
                            (
                                "raw-chat-without-topic".to_owned(),
                                direct_chat_option_label(locale, &title, None, &None, None),
                            ),
                        ],
                        Rc::new(move |next| {
                            let next_value = next;
                            selected.revise(|current| *current = next_value)
                        }),
                    ),
                )))
            },
        )
    }
    // Exercise the production browser factory against the semantic model. Native
    // admission and actual callbacks are covered separately below.
    fn rendered_options(app: &glory::App) -> (BTreeMap<String, String>, Option<String>) {
        fn visit(
            app: &glory::App,
            id: glory::render::NodeId,
            options: &mut BTreeMap<String, String>,
            selected: &mut Option<String>,
        ) {
            let tree = app.tree();
            let node = tree.node(id).unwrap();
            if let glory::render::Props::Select(props) = node.descriptor.view().props {
                let is_actions = props.options().count() == 13;
                for (option, _) in props.options() {
                    options.insert(option.value.clone(), option.label.clone());
                    if is_actions && props.selection.keys.contains(&option.key) {
                        *selected = Some(option.value.clone());
                    }
                }
            }
            for child in &node.children {
                visit(app, *child, options, selected);
            }
        }
        let mut options = BTreeMap::new();
        let mut selected = None;
        for root in app.tree().roots() {
            visit(app, *root, &mut options, &mut selected);
        }
        (options, selected)
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_direct_choice_keeps_full_protocol_values_and_real_selection_callbacks() {
        fn nodes(app: &glory::App, class: &str) -> Vec<glory::render::NodeId> {
            fn visit(
                tree: &glory::render::memory::Memory,
                id: glory::render::NodeId,
                class: &str,
                result: &mut Vec<glory::render::NodeId>,
            ) {
                let node = tree.node(id).unwrap();
                if node
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|value| value == class)
                {
                    result.push(id);
                }
                assert!(!matches!(
                    node.descriptor.view().props,
                    glory::render::Props::Select(_)
                ));
                for child in &node.children {
                    visit(tree, *child, class, result);
                }
            }
            let tree = app.tree();
            let mut result = vec![];
            for root in tree.roots() {
                visit(&tree, *root, class, &mut result);
            }
            result
        }
        let app = glory::App::memory();
        let first = "ak:strand:full-protocol-identity/原始名称";
        let second = "ak:strand:another-identity/metadata?value=untouched";
        let selected = app.scope().cage(first.to_owned());
        let changes = app.scope().cage(Vec::new());
        app.mount(structure_select(
            app.scope(),
            "direct-contract",
            "Chats",
            selected,
            vec![
                (first.into(), "First chat".into()),
                (second.into(), "Second chat".into()),
            ],
            Rc::new(move |next| {
                changes.revise(|values| values.push(next.clone()));
                selected.revise(|value| *value = next);
            }),
        ))
        .unwrap();
        let trigger = nodes(&app, "native-choice-trigger")[0];
        for (index, expected) in [(1, second), (0, first)] {
            assert!(
                app.dispatch(trigger, glory::render::Event::Activate)
                    .unwrap()
            );
            app.flush().unwrap();
            let options = nodes(&app, "native-choice-option");
            assert_eq!(options.len(), 2);
            assert!(
                app.dispatch(options[index], glory::render::Event::Activate)
                    .unwrap()
            );
            app.flush().unwrap();
            assert_eq!(selected.get_untracked(), expected);
            assert_eq!(nodes(&app, "native-choice-trigger"), vec![trigger]);
        }
        assert_eq!(
            changes.get_untracked(),
            vec![second.to_owned(), first.to_owned()]
        );
    }
    #[test]
    fn retained_direct_labels_preserve_actions_typed_state_counts_and_original_metadata() {
        let handles = Rc::new(RefCell::new(Handles::default()));
        let app = glory::App::memory();
        let capture = handles.clone();
        app.mount(widget(move |scope| {
            retained_direct_labels(scope, capture.clone()).build(scope)
        }))
        .unwrap();
        app.flush().unwrap();
        let locale = handles.borrow().locale.unwrap();
        let action = handles.borrow().action.unwrap();
        let title = handles.borrow().title.unwrap();
        let topic = handles.borrow().topic.unwrap();
        let unread = handles.borrow().unread.unwrap();
        let state = handles.borrow().state.unwrap();
        for count in [None, Some(0), Some(7), Some(usize::MAX)] {
            for object_state in [
                None,
                Some(arkret_sdk::ObjectState::Active),
                Some(arkret_sdk::ObjectState::Archived),
            ] {
                for wire_action in ACTIONS {
                    {
                        let next_value = count;
                        unread.revise(|current| *current = next_value)
                    };
                    {
                        let next_value = object_state.clone();
                        state.revise(|current| *current = next_value)
                    };
                    {
                        let next_value = wire_action.to_owned();
                        action.revise(|current| *current = next_value)
                    };
                    {
                        let next_value = UiLocale::En;
                        locale.revise(|current| *current = next_value)
                    };
                    app.flush().unwrap();
                    let (english, _) = rendered_options(&app);
                    for language in [UiLocale::Zh, UiLocale::En] {
                        {
                            let next_value = language;
                            locale.revise(|current| *current = next_value)
                        };
                        app.flush().unwrap();
                        let (options, selected_action) = rendered_options(&app);
                        assert_eq!(options.len(), 15);
                        let labels = if language == UiLocale::Zh {
                            CHINESE
                        } else {
                            ENGLISH
                        };
                        for (value, label) in ACTIONS.into_iter().zip(labels) {
                            assert_eq!(options.get(value).map(String::as_str), Some(label));
                        }
                        let suffix = count
                            .map(|count| {
                                if language == UiLocale::Zh {
                                    format!("（{count} 条未读）")
                                } else {
                                    format!(" ({count} unread)")
                                }
                            })
                            .unwrap_or_default();
                        let archived = if object_state == Some(arkret_sdk::ObjectState::Archived) {
                            if language == UiLocale::Zh {
                                "（已归档）"
                            } else {
                                " (archived)"
                            }
                        } else {
                            ""
                        };
                        assert_eq!(
                            options.get("raw-chat"),
                            Some(&format!("{RAW_TITLE}{suffix}{archived} · {RAW_TOPIC}"))
                        );
                        assert_eq!(
                            options.get("raw-chat-without-topic").map(String::as_str),
                            Some(RAW_TITLE)
                        );
                        assert_eq!(selected_action.as_deref(), Some(wire_action));
                        assert_eq!(action.get(), wire_action);
                        assert_eq!(title.get(), RAW_TITLE);
                        assert_eq!(topic.get(), RAW_TOPIC);
                        assert_eq!(unread.get(), count);
                        assert_eq!(state.get(), object_state);
                        assert_eq!(
                            handles.borrow().initializations,
                            5,
                            "locale changes retain every original state cell"
                        );
                        if language == UiLocale::En {
                            assert_eq!(options, english);
                        }
                    }
                }
            }
        }
    }
}
