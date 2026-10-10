//! Seal standard user metadata before the single Event authoring boundary.

use arkret_sdk::{SpaceMetadata, StrandMetadata, event_spec};

use super::*;

impl EventSubmitter {
    pub(super) async fn retain_authored_metadata(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<()> {
        if !matches!(
            event.kind,
            arkret_sdk::EventKind::SpaceCreate
                | arkret_sdk::EventKind::SpaceUpdate
                | arkret_sdk::EventKind::StrandCreate
                | arkret_sdk::EventKind::StrandUpdate
        ) || (event
            .payload
            .get("object")
            .and_then(|value| value.get("encrypted_metadata"))
            .is_none()
            && event
                .payload
                .get("patch")
                .and_then(|value| value.pointer("/encrypted_metadata/value"))
                .is_none())
        {
            return Ok(());
        }
        let Some(store) = self.state_store.as_ref() else {
            return Ok(());
        };
        let session_epoch = crate::identity::device_directory::session_cache_epoch();
        let authority = self.authority()?;
        let changed = store.write(|state| {
            anyhow::ensure!(
                state.active_authority().as_ref() == Some(authority),
                "Metadata backup crossed its account fence"
            );
            retain_metadata_plaintext(state, event)
        })?;
        if changed {
            store
                .read(|state| state.begin_durable_flush())?
                .wait()
                .await?;
            anyhow::ensure!(
                crate::identity::device_directory::session_cache_epoch() == session_epoch
                    && store
                        .read(crate::state::LocalStateStore::active_authority)
                        .as_ref()
                        == Some(authority),
                "Metadata backup crossed its session fence"
            );
        }
        Ok(())
    }

    pub(super) async fn prepare_metadata(
        &self,
        intent: EventIntent,
    ) -> anyhow::Result<EventIntent> {
        if !matches!(
            intent.kind(),
            arkret_sdk::EventKind::SpaceCreate
                | arkret_sdk::EventKind::SpaceUpdate
                | arkret_sdk::EventKind::StrandCreate
                | arkret_sdk::EventKind::StrandUpdate
        ) || !matches!(
            intent.scope_ref(),
            arkret_sdk::ScopeRef::Realm { .. } | arkret_sdk::ScopeRef::Circle { .. }
        ) {
            return Ok(intent);
        }
        let body = crate::mls::send_gate::ApplicationBody::of_event(&intent)?;
        let changes_profile = intent.kind() == &arkret_sdk::EventKind::StrandUpdate
            && intent
                .payload()
                .get("patch")
                .is_some_and(|patch| patch.get("schema_refs").is_some());
        if !matches!(
            &body,
            Some(crate::mls::send_gate::ApplicationBody::Plaintext)
        ) && !(body.is_none() && changes_profile)
        {
            return Ok(intent);
        }
        let input = self
            .mls_send_gate_input(intent.scope_ref())
            .ok_or_else(|| anyhow::anyhow!("Metadata current state is unavailable"))?;
        let endpoint = crate::secure_key_store::active_device_seed_scope()
            .ok_or_else(|| anyhow::anyhow!("Metadata device is unavailable"))?;
        anyhow::ensure!(
            &endpoint.authority == self.authority()?,
            "Metadata belongs to another account"
        );
        let gate = crate::mls::send_gate::resolve_restorable_mls_send_gate(
            &input,
            intent.scope_ref(),
            &endpoint.device_id,
        )
        .await?;
        if matches!(gate, crate::mls::send_gate::MlsSendGate::Plaintext) {
            return Ok(intent);
        }
        let store = self
            .state_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Metadata store is unavailable"))?;
        let realm = intent
            .realm_id_opt()
            .ok_or_else(|| anyhow::anyhow!("Metadata Realm is unavailable"))?;
        let open = |id: &str, strand: bool| -> anyhow::Result<Value> {
            store.read(|state| {
                let entries = state.realm_current_state_entries(realm.as_str());
                let values = entries
                    .iter()
                    .filter_map(|entry| {
                        let arkret_sdk::TypedCurrentRow::Value {
                            selector, value, ..
                        } = entry;
                        let matches = match selector {
                            arkret_sdk::CurrentSelector::Space { space_id } => {
                                !strand && space_id.as_str() == id
                            }
                            arkret_sdk::CurrentSelector::Strand { strand_id } => {
                                strand && strand_id.as_str() == id
                            }
                            _ => false,
                        };
                        matches.then_some(value)
                    })
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    values.len() == 1,
                    "Metadata requires one exact current object"
                );
                let value = values[0];
                if let Some(envelope) = value.get("encrypted_metadata") {
                    let envelope = serde_json::from_value(envelope.clone())?;
                    crate::views::metadata::open_metadata(
                        state,
                        realm.as_str(),
                        id,
                        &envelope,
                        &endpoint.authority,
                        &endpoint.device_id,
                    )
                    .ok_or_else(|| anyhow::anyhow!("Current metadata cannot be decrypted"))
                } else if strand {
                    Ok(value
                        .get("metadata")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({})))
                } else {
                    let fields = value
                        .get("fields")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|(key, _)| !machine_field(key))
                        .collect();
                    Ok(serde_json::to_value(SpaceMetadata {
                        title: value
                            .get("title")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        summary: value
                            .get("summary")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        labels: serde_json::from_value(
                            value
                                .get("labels")
                                .cloned()
                                .unwrap_or_else(|| serde_json::json!([])),
                        )?,
                        fields,
                        avatar_blob_ref: serde_json::from_value(
                            value.get("avatar_blob_ref").cloned().unwrap_or(Value::Null),
                        )?,
                    })?)
                }
            })
        };
        let seal = |metadata: &Value| -> anyhow::Result<arkret_sdk::EncryptedEnvelope> {
            let bytes = serde_json::to_vec(metadata)?;
            let secure = crate::secure_key_store::default_secure_key_store("inkson");
            let scope = intent.scope_ref();
            let encryption = store.write(|state| {
                let snapshot = state
                    .mls_checkpoint_for_scope(scope)
                    .ok_or_else(|| anyhow::anyhow!("Metadata MLS checkpoint is unavailable"))?;
                let group_ref = state
                    .mls_group_state_ref_for_scope(scope, &snapshot.group_id, snapshot.epoch)
                    .map_err(anyhow::Error::msg)?;
                let (circle, sidecar) = match scope {
                    arkret_sdk::ScopeRef::Circle { circle_id, .. } => {
                        (Some(circle_id.as_str()), None)
                    }
                    arkret_sdk::ScopeRef::Sidecar { sidecar_id, .. } => (None, Some(sidecar_id)),
                    _ => (None, None),
                };
                crate::mls::runtime::encrypt_message_with_device_snapshot(
                    state,
                    secure.as_ref(),
                    realm.as_str(),
                    &endpoint.authority,
                    &endpoint.device_id,
                    "application/json",
                    intent.kind().as_str(),
                    group_ref,
                    &bytes,
                    None,
                    None,
                    None,
                    circle,
                    sidecar,
                )
                .map_err(|error| anyhow::anyhow!(error.user_message()))
            })?;
            Ok(arkret_sdk::mls::encrypted_envelope_from_payload(
                &encryption.content,
            )?)
        };
        if intent.kind() == &arkret_sdk::EventKind::StrandUpdate {
            let payload = intent.typed_payload::<event_spec::StrandUpdate>()?;
            let current = store.read(|state| {
                let entries = state.realm_current_state_entries(realm.as_str());
                let mut values = entries.iter().filter_map(|entry| {
                    let arkret_sdk::TypedCurrentRow::Value { selector, value, .. } = entry;
                    matches!(selector, arkret_sdk::CurrentSelector::Strand { strand_id } if strand_id == &payload.target_ref)
                        .then_some(value)
                });
                let current = values.next().cloned();
                anyhow::ensure!(values.next().is_none(), "Metadata current object is ambiguous");
                current.ok_or_else(|| anyhow::anyhow!("Metadata current object is unavailable"))
            })?;
            let current: arkret_sdk::Strand = serde_json::from_value(current)?;
            validate_strand_metadata_patch(
                &current,
                open(payload.target_ref.as_str(), true)?,
                &payload.patch,
            )?;
        }
        let prepared = seal_metadata(&intent, open, seal)?;
        let barrier = store.read(|state| state.begin_durable_flush())?;
        barrier.wait().await?;
        anyhow::ensure!(
            crate::secure_key_store::active_device_seed_scope().as_ref() == Some(&endpoint),
            "Metadata account or device changed while sealing"
        );
        Ok(prepared)
    }
}

/// Use the final authored identity and the exact ciphertext digest. Draft IDs
/// cannot name a create object's private backup, and mutable field paths would
/// let an older backup mask a newer encrypted metadata revision.
fn retain_metadata_plaintext(
    store: &mut crate::state::LocalStateStore,
    event: &arkret_sdk::Event,
) -> anyhow::Result<bool> {
    let (id, envelope, strand) = match event.kind {
        arkret_sdk::EventKind::SpaceCreate => {
            let payload: arkret_sdk::SpaceCreatePayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            (
                arkret_sdk::SpaceId::from_event_id(&event.event_id).to_string(),
                payload.object.encrypted_metadata,
                false,
            )
        }
        arkret_sdk::EventKind::StrandCreate => {
            let payload: arkret_sdk::StrandCreatePayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            (
                arkret_sdk::StrandId::from_event_id(&event.event_id).to_string(),
                payload.object.encrypted_metadata,
                true,
            )
        }
        arkret_sdk::EventKind::SpaceUpdate => {
            let payload: arkret_sdk::SpacePatchPayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            (
                payload.space_id.to_string(),
                payload
                    .patch
                    .as_ref()
                    .map(metadata_patch_envelope)
                    .transpose()?
                    .flatten(),
                false,
            )
        }
        arkret_sdk::EventKind::StrandUpdate => {
            let payload: arkret_sdk::StrandPatchPayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            (
                payload.target_ref.to_string(),
                metadata_patch_envelope(&payload.patch)?,
                true,
            )
        }
        _ => return Ok(false),
    };
    let Some(envelope) = envelope else {
        return Ok(false);
    };
    let digest = envelope.payload_digest()?;
    let Some(bytes) = store.mls_decrypted_plaintext_for(event.realm_id.as_str(), digest.as_str())
    else {
        return Ok(false);
    };
    let metadata: Value = serde_json::from_slice(&bytes)?;
    if strand {
        let _: StrandMetadata = serde_json::from_value(metadata)?;
    } else {
        serde_json::from_value::<SpaceMetadata>(metadata)?.validate()?;
    }
    store.save_private_plaintext(
        event.realm_id.as_str(),
        &id,
        &format!("encrypted_metadata:{digest}"),
        std::str::from_utf8(&bytes)?,
    );
    Ok(true)
}

fn metadata_patch_envelope(
    patch: &arkret_sdk::Patch,
) -> anyhow::Result<Option<arkret_sdk::EncryptedEnvelope>> {
    let value = serde_json::to_value(patch)?;
    value
        .pointer("/encrypted_metadata/value")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

fn machine_field(key: &str) -> bool {
    matches!(key, "wip_limit" | "wip_limit_enforcement" | "view_id")
}

fn validate_plaintext_strand_profile(strand: &arkret_sdk::Strand) -> anyhow::Result<()> {
    strand.validate_profile_activation()?;
    if let Some(metadata) = &strand.metadata {
        arkret_models_collaboration::objects::productivity::validate_calendar_event_metadata_fields(&metadata.fields)?;
    }
    Ok(())
}

fn validate_strand_metadata_patch(
    current: &arkret_sdk::Strand,
    plaintext: Value,
    patch: &arkret_sdk::Patch,
) -> anyhow::Result<()> {
    let mut opened = serde_json::to_value(current)?;
    opened
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("serialized Strand metadata is not an object"))?
        .remove("encrypted_metadata");
    opened["metadata"] = plaintext;
    let post: arkret_sdk::Strand = serde_json::from_value(patch.apply(&opened)?)?;
    validate_plaintext_strand_profile(&post)
}

fn seal_metadata(
    intent: &EventIntent,
    mut open: impl FnMut(&str, bool) -> anyhow::Result<Value>,
    mut seal: impl FnMut(&Value) -> anyhow::Result<arkret_sdk::EncryptedEnvelope>,
) -> anyhow::Result<EventIntent> {
    match intent.kind() {
        arkret_sdk::EventKind::SpaceCreate => {
            let mut payload = intent.typed_payload::<event_spec::SpaceCreate>()?;
            let object = &mut payload.object;
            if object.encrypted_metadata.is_some() {
                return Ok(intent.clone());
            }
            let metadata = SpaceMetadata {
                title: object
                    .title
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Space title is missing"))?,
                summary: object.summary.take(),
                labels: std::mem::take(&mut object.labels),
                fields: object
                    .fields
                    .iter()
                    .filter(|(key, _)| !machine_field(key))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
                avatar_blob_ref: object.avatar_blob_ref.take(),
            };
            metadata.validate()?;
            object.fields.retain(|key, _| machine_field(key));
            object.encrypted_metadata = Some(seal(&serde_json::to_value(metadata)?)?);
            replace_payload::<event_spec::SpaceCreate>(intent, payload)
        }
        arkret_sdk::EventKind::StrandCreate => {
            let mut payload = intent.typed_payload::<event_spec::StrandCreate>()?;
            if payload.object.encrypted_metadata.is_some() {
                return Ok(intent.clone());
            }
            validate_plaintext_strand_profile(&payload.object)?;
            if let Some(metadata) = payload.object.metadata.take() {
                payload.object.encrypted_metadata = Some(seal(&serde_json::to_value(metadata)?)?);
            }
            replace_payload::<event_spec::StrandCreate>(intent, payload)
        }
        arkret_sdk::EventKind::SpaceUpdate => {
            let mut payload = intent.typed_payload::<event_spec::SpaceUpdate>()?;
            if let Some(patch) = payload.patch.take() {
                payload.patch = Some(seal_patch(
                    patch,
                    payload.space_id.as_str(),
                    false,
                    &mut open,
                    &mut seal,
                )?);
            }
            replace_payload::<event_spec::SpaceUpdate>(intent, payload)
        }
        arkret_sdk::EventKind::StrandUpdate => {
            let mut payload = intent.typed_payload::<event_spec::StrandUpdate>()?;
            payload.patch = seal_patch(
                payload.patch,
                payload.target_ref.as_str(),
                true,
                &mut open,
                &mut seal,
            )?;
            replace_payload::<event_spec::StrandUpdate>(intent, payload)
        }
        _ => Ok(intent.clone()),
    }
}

fn seal_patch(
    patch: arkret_sdk::Patch,
    id: &str,
    strand: bool,
    open: &mut impl FnMut(&str, bool) -> anyhow::Result<Value>,
    seal: &mut impl FnMut(&Value) -> anyhow::Result<arkret_sdk::EncryptedEnvelope>,
) -> anyhow::Result<arkret_sdk::Patch> {
    let (private, mut structural): (BTreeMap<_, _>, BTreeMap<_, _>) = patch
        .iter()
        .map(|(path, op)| (path.clone(), op.clone()))
        .partition(|(path, _)| {
            if strand {
                path == "metadata" || path.starts_with("metadata.")
            } else {
                matches!(
                    path.as_str(),
                    "title" | "summary" | "labels" | "avatar_blob_ref" | "fields"
                ) || path
                    .strip_prefix("fields.")
                    .is_some_and(|field| !machine_field(field))
            }
        });
    if private.is_empty() {
        return Ok(patch);
    }
    anyhow::ensure!(
        !structural.contains_key("encrypted_metadata"),
        "Metadata patch contains plaintext and ciphertext"
    );
    let current = open(id, strand)?;
    let post = if strand {
        let updated =
            patch_from_entries(private)?.apply(&serde_json::json!({"metadata": current}))?;
        updated
            .get("metadata")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Strand metadata was removed"))?
    } else {
        patch_from_entries(private)?.apply(&current)?
    };
    if strand {
        let _: StrandMetadata = serde_json::from_value(post.clone())?;
    } else {
        serde_json::from_value::<SpaceMetadata>(post.clone())?.validate()?;
    }
    structural.insert(
        "encrypted_metadata".to_owned(),
        arkret_sdk::PatchOp::set(serde_json::to_value(seal(&post)?)?),
    );
    patch_from_entries(structural)
}

fn patch_from_entries(
    entries: BTreeMap<String, arkret_sdk::PatchOp>,
) -> anyhow::Result<arkret_sdk::Patch> {
    let mut patch = arkret_sdk::Patch::new();
    for (path, op) in entries {
        patch.insert_op(path, op)?;
    }
    Ok(patch)
}

fn replace_payload<K: arkret_sdk::EventSpec>(
    intent: &EventIntent,
    payload: K::Payload,
) -> anyhow::Result<EventIntent> {
    anyhow::ensure!(
        intent.kind() == &K::KIND,
        "Metadata cannot change the Event kind"
    );
    K::validate_payload(&payload)?;
    // The SDK owns both closed carriers. Preserve every producer-selected
    // field and replace only its validated, still unauthored typed body.
    let mut value = serde_json::to_value(intent)?;
    value["payload"] = serde_json::to_value(payload)?;
    Ok(serde_json::from_value(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const SPACE: &str = "ak:space:Af1Pi9BryFSPKbIS5B4pB9_rXFtOAL3hL4MoyX6i-uCE";

    fn actor() -> arkret_sdk::ActorId {
        crate::test_support::account_actor("ak:did_core:web:alice.example")
    }

    fn scope() -> arkret_sdk::ScopeRef {
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
        }
    }

    fn encrypt(kind: &str, metadata: &Value) -> arkret_sdk::EncryptedEnvelope {
        let device =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap();
        let identity =
            arkret_sdk::ArkretMlsIdentity::new_test_human_device(actor(), device).unwrap();
        let mut group = identity.create_group(&scope()).unwrap();
        let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            "application/json",
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
            scope(),
            kind,
            group.epoch(),
            arkret_sdk::EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM")
                .unwrap(),
            group.local_content_sender_domain().unwrap(),
            arkret_sdk::EventContentRoutingContext::None,
        )
        .unwrap();
        let payload = group
            .encrypt_payload(header, &serde_json::to_vec(metadata).unwrap())
            .unwrap();
        arkret_sdk::mls::encrypted_envelope_from_payload(&payload).unwrap()
    }

    #[test]
    fn metadata_create_seals_complete_user_fields_and_keeps_structure() {
        let mut object = arkret_sdk::Space::create_object(
            arkret_sdk::RealmId::new(REALM).unwrap(),
            "list",
            "Private title",
            actor(),
        );
        object.parent_space_id = Some(arkret_sdk::SpaceId::new(SPACE).unwrap());
        object.rank = Some("U".to_owned());
        object.summary = Some("Private summary".to_owned());
        object.labels = vec!["Private label".to_owned()];
        object
            .fields
            .insert("custom".to_owned(), serde_json::json!("Private extension"));
        object
            .fields
            .insert("wip_limit".to_owned(), serde_json::json!(3));
        let intent = arkret_sdk::TypedEventDraft::<event_spec::SpaceCreate>::new(
            scope(),
            actor(),
            arkret_sdk::SpaceCreatePayload::new(object),
        )
        .unwrap()
        .into_intent(crate::clock::now_utc())
        .unwrap();
        let prepared = seal_metadata(
            &intent,
            |_, _| panic!("create cannot read another object"),
            |value| {
                let metadata: SpaceMetadata = serde_json::from_value(value.clone())?;
                metadata.validate()?;
                assert_eq!(metadata.title, "Private title");
                assert_eq!(metadata.summary.as_deref(), Some("Private summary"));
                assert_eq!(metadata.labels, ["Private label"]);
                assert_eq!(metadata.fields.len(), 1);
                assert_eq!(metadata.fields["custom"], "Private extension");
                Ok(encrypt(intent.kind().as_str(), value))
            },
        )
        .unwrap();
        let object = prepared
            .typed_payload::<event_spec::SpaceCreate>()
            .unwrap()
            .object;
        assert!(object.title.is_none() && object.summary.is_none() && object.labels.is_empty());
        assert!(object.encrypted_metadata.is_some());
        assert_eq!(object.fields.len(), 1);
        assert_eq!(object.fields["wip_limit"], 3);
        assert_eq!(object.rank.as_deref(), Some("U"));
        assert_eq!(object.parent_space_id.unwrap().as_str(), SPACE);
        assert_eq!(prepared.actor_id(), intent.actor_id());
        assert_eq!(prepared.scope_ref(), intent.scope_ref());
        assert_eq!(prepared.created_at(), intent.created_at());
    }

    #[test]
    fn metadata_card_create_seals_title_and_profile_without_encrypting_tracks() {
        let mut object = arkret_sdk::Strand::new_create(
            arkret_sdk::RealmId::new(REALM).unwrap(),
            "Private card",
            actor(),
        );
        object
            .metadata
            .as_mut()
            .unwrap()
            .fields
            .insert("strand_kind".to_owned(), serde_json::json!("card"));
        let original_tracks = serde_json::to_value(&object.tracks).unwrap();
        let intent = arkret_sdk::TypedEventDraft::<event_spec::StrandCreate>::new(
            scope(),
            actor(),
            arkret_sdk::StrandCreatePayload { object },
        )
        .unwrap()
        .into_intent(crate::clock::now_utc())
        .unwrap();
        let prepared = seal_metadata(
            &intent,
            |_, _| panic!("create cannot read another object"),
            |value| {
                let metadata: StrandMetadata = serde_json::from_value(value.clone())?;
                assert_eq!(metadata.title.as_deref(), Some("Private card"));
                assert_eq!(metadata.fields["strand_kind"], "card");
                Ok(encrypt(intent.kind().as_str(), value))
            },
        )
        .unwrap();
        let object = prepared
            .typed_payload::<event_spec::StrandCreate>()
            .unwrap()
            .object;
        assert!(object.metadata.is_none() && object.encrypted_metadata.is_some());
        assert_eq!(
            serde_json::to_value(object.tracks).unwrap(),
            original_tracks
        );
    }

    #[test]
    fn metadata_rename_preserves_unedited_user_fields_and_structural_patch() {
        let mut patch = arkret_sdk::Patch::new();
        patch.insert("title", "New title").unwrap();
        patch.insert("rank", "V").unwrap();
        let result = seal_patch(patch, SPACE, false, &mut |id, strand| {
            assert_eq!(id, SPACE);
            assert!(!strand);
            Ok(serde_json::json!({"title":"Old title", "summary":"Keep summary", "labels":["Keep label"], "fields":{"custom":"Keep extension"}}))
        }, &mut |value| {
            assert_eq!(value["title"], "New title");
            assert_eq!(value["summary"], "Keep summary");
            assert_eq!(value["labels"][0], "Keep label");
            assert_eq!(value["fields"]["custom"], "Keep extension");
            Ok(encrypt("ak.space.update", value))
        }).unwrap();
        let value = serde_json::to_value(result).unwrap();
        assert!(value.get("title").is_none());
        assert_eq!(value["rank"], "V");
        assert!(value.get("encrypted_metadata").is_some());
    }

    #[test]
    fn encrypted_calendar_patch_validates_private_fields_and_public_profile_before_sealing() {
        let source = arkret_sdk::EventId::from_digest(
            scope()
                .realm_id_opt()
                .unwrap()
                .digest_suite_code()
                .digest_suite(),
            [5; 32],
        );
        let mut current = arkret_sdk::Strand::discussion(
            arkret_sdk::StrandId::from_event_id(&source),
            REALM.parse().unwrap(),
            "Private schedule",
            actor(),
        );
        let plaintext = serde_json::json!({"title":"Private schedule","fields":{"calendar":{
            "start":"2026-06-22","end":"2026-06-23","timezone":"UTC",
            "tzdb_version":"2025b","all_day":true,"status":"confirmed"
        }}});
        current.metadata = None;
        current.encrypted_metadata = Some(encrypt("ak.strand.create", &plaintext));
        current.schema_refs = Some(vec!["ak.schema.calendar_event.v1".to_owned()]);
        let mut rename = arkret_sdk::Patch::new();
        rename.insert("metadata.title", "Renamed schedule").unwrap();
        validate_strand_metadata_patch(&current, plaintext.clone(), &rename).unwrap();
        let unpair: arkret_sdk::Patch = serde_json::from_value(serde_json::json!({
            "schema_refs":{"$op":"unset"}
        }))
        .unwrap();
        assert!(validate_strand_metadata_patch(&current, plaintext.clone(), &unpair).is_err());
        let mut invalid = rename;
        invalid
            .insert("metadata.fields.calendar.timezone", "Invalid/Timezone")
            .unwrap();
        assert!(validate_strand_metadata_patch(&current, plaintext, &invalid).is_err());
        assert!(current.metadata.is_none());
    }

    #[test]
    fn authored_metadata_backup_restores_final_object_and_exact_ciphertext_revision() {
        let directory = tempfile::tempdir().unwrap();
        let mut source =
            crate::state::LocalStateStore::with_path(directory.path().join("source.json"));
        let mut restored =
            crate::state::LocalStateStore::with_path(directory.path().join("restored.json"));
        let object = arkret_sdk::Space::create_object(
            arkret_sdk::RealmId::new(REALM).unwrap(),
            "board",
            "Restored board",
            actor(),
        );
        let intent = arkret_sdk::TypedEventDraft::<event_spec::SpaceCreate>::new(
            scope(),
            actor(),
            arkret_sdk::SpaceCreatePayload::new(object),
        )
        .unwrap()
        .into_intent(crate::clock::now_utc())
        .unwrap();
        let mut authored_plaintext = None;
        let prepared = seal_metadata(
            &intent,
            |_, _| panic!("create has no current"),
            |value| {
                let envelope = encrypt(intent.kind().as_str(), value);
                authored_plaintext = Some((envelope.payload_digest()?, serde_json::to_vec(value)?));
                Ok(envelope)
            },
        )
        .unwrap();
        let authored = prepared
            .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap();
        let event = authored.event();
        let id = arkret_sdk::SpaceId::from_event_id(&event.event_id).to_string();
        let payload: arkret_sdk::SpaceCreatePayload =
            serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();
        let envelope = payload.object.encrypted_metadata.unwrap();
        let (digest, plaintext) = authored_plaintext.unwrap();
        source
            .retain_authored_mls_plaintext(REALM, &digest, &plaintext)
            .unwrap();
        assert!(
            source.private_plaintext_is_empty(),
            "device digest cache is not a cross-device backup"
        );
        assert!(retain_metadata_plaintext(&mut source, event).unwrap());
        let backup = source.private_plaintext_snapshot_json();
        restored.merge_private_plaintext_map(serde_json::from_slice(&backup).unwrap());
        assert!(
            restored
                .mls_decrypted_plaintext_for(REALM, digest.as_str())
                .is_none()
        );
        let device =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap();
        let opened = crate::views::metadata::open_metadata(
            &restored,
            REALM,
            &id,
            &envelope,
            actor().as_account_id().unwrap(),
            &device,
        )
        .expect("fresh device opens its restored authored metadata without replaying MLS");
        assert_eq!(opened["title"], "Restored board");
        assert!(
            crate::views::metadata::open_metadata(
                &restored,
                REALM,
                SPACE,
                &envelope,
                actor().as_account_id().unwrap(),
                &device,
            )
            .is_none(),
            "backup must not supply plaintext under another object identity"
        );
        let other = encrypt(
            "ak.space.create",
            &serde_json::json!({"title":"Another revision"}),
        );
        assert!(
            crate::views::metadata::open_metadata(
                &restored,
                REALM,
                &id,
                &other,
                actor().as_account_id().unwrap(),
                &device,
            )
            .is_none(),
            "another ciphertext revision must not reuse the restored title"
        );
        assert!(
            !serde_json::to_string(event)
                .unwrap()
                .contains("Restored board")
        );
    }
}
