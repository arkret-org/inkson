//! Bounded local candidates. Every original is installed with its verified
//! Account frame, and is invisible until that frame's durable publication.
use arkret_sdk::{CommittedEventFullView, EventKind, MessageId};
use serde_json::Value;

use super::*;

impl super::super::LocalStateStore {
    pub(crate) fn search_session_matches(
        &self,
        account: &AccountId,
        device: &arkret_sdk::DeviceId,
    ) -> bool {
        if self.active_authority().as_ref() != Some(account)
            || self.current_reset_required()
            || self.persist_error().is_some()
        {
            return false;
        }
        self.with_unoverlaid_account_fields(|state| {
            let now = chrono::Utc::now();
            state.session_grant.as_ref().is_some_and(|grant| {
                grant.account_id == *account
                    && grant.device_id == *device
                    && grant.grant_expires_at.is_some_and(|expiry| expiry > now)
            }) && state
                .device_authoring_authority
                .as_ref()
                .is_some_and(|authority| {
                    authority.account_id == *account
                        && authority.device_id == *device
                        && authority.device_projection.device_status.is_active()
                        && authority.device_projection.attested_at <= now
                        && authority.device_projection.expires_at > now
                        && authority.device_projection.authorization_window.not_before <= now
                        && authority.device_projection.authorization_window.expires_at.is_none_or(|expiry| expiry > now)
                        && crate::identity::authoring_generation::cached_principal_authoring_generation(account, device.as_str()).is_none_or(|generation| generation == authority.authoring_generation)
                })
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SearchRecord {
    create: Option<CommittedEventFullView>,
    revision: Option<CommittedEventFullView>,
    redacted: bool,
}

pub(crate) struct SearchPage {
    pub rows: Vec<CommittedEventFullView>,
    pub next: Option<String>,
    pub generation: u64,
}

fn target(full: &CommittedEventFullView) -> anyhow::Result<Option<MessageId>> {
    let event = &full.event;
    let message = match event.kind {
        EventKind::MessageCreate => MessageId::from_event_id(&event.event_id),
        EventKind::MessageRevise | EventKind::MessageRedact => {
            let id = event
                .payload
                .get("message_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("message control has no exact target"))?;
            MessageId::new(id.to_owned())?
        }
        _ => return Ok(None),
    };
    full.validate_shape()?;
    anyhow::ensure!(
        full.commit.event_ref == event.event_id
            && full.commit.realm_id == event.realm_id
            && full.commit.stream_ref
                == arkret_sdk::CommitStreamRef::from_scope(&event.scope_ref, None)?,
        "search original and covering Commit disagree"
    );
    Ok(Some(message))
}

impl CurrentIndex {
    pub(super) async fn stage_search_rows(
        &self,
        incoming: &arkret_sdk::sync::RealmSyncEntry,
        committed: u64,
        suffix: &str,
        writes: &mut BTreeMap<String, Vec<u8>>,
        targets: &mut BTreeMap<String, Vec<u8>>,
    ) -> anyhow::Result<()> {
        for view in incoming.committed_events.iter().flatten() {
            let arkret_sdk::CommittedEventView::Full(full) = view else {
                writes.insert(
                    format!(
                        "{}search-withheld/{}/{suffix}",
                        self.prefix,
                        view.commit().event_ref
                    ),
                    serde_json::to_vec(&true)?,
                );
                continue;
            };
            let Some(message) = target(full)? else {
                continue;
            };
            // Native Sidecar exchanges have their own private reducer. A public
            // Strand locator never makes their plaintext a shared search input.
            if !matches!(
                full.event.scope_ref,
                arkret_sdk::ScopeRef::Realm { .. } | arkret_sdk::ScopeRef::Circle { .. }
            ) {
                continue;
            }
            let prefix = format!("{}search/{}/", self.prefix, message);
            let key = format!("{prefix}{suffix}");
            let mut record: SearchRecord = match writes.get(&key) {
                Some(bytes) => serde_json::from_slice(bytes)?,
                None => self.latest(&prefix, committed).await?.unwrap_or_default(),
            };
            if let Some(create) = &record.create {
                anyhow::ensure!(
                    create.event.realm_id == full.event.realm_id
                        && create.event.scope_ref == full.event.scope_ref
                        && create.commit.stream_ref == full.commit.stream_ref,
                    "search control crosses the target security scope"
                );
            }
            if let Some(revision) = &record.revision {
                anyhow::ensure!(
                    revision.event.realm_id == full.event.realm_id
                        && revision.event.scope_ref == full.event.scope_ref,
                    "search original crosses a retained revision scope"
                );
            }
            match full.event.kind {
                EventKind::MessageCreate => {
                    if let Some(old) = &record.create {
                        anyhow::ensure!(old == full, "search create changes an accepted original");
                    } else {
                        record.create = Some(full.clone());
                    }
                }
                EventKind::MessageRevise => {
                    if let Some(old) = &record.revision {
                        anyhow::ensure!(
                            old.commit.stream_ref == full.commit.stream_ref,
                            "search revision crosses streams"
                        );
                        if old.commit.stream_position == full.commit.stream_position {
                            anyhow::ensure!(old == full, "search revision forks its Commit");
                        }
                    }
                    if record
                        .revision
                        .as_ref()
                        .is_none_or(|old| old.commit.stream_position < full.commit.stream_position)
                    {
                        record.revision = Some(full.clone());
                    }
                }
                EventKind::MessageRedact => record.redacted = true,
                _ => unreachable!(),
            }
            writes.insert(key, serde_json::to_vec(&record)?);
            targets.insert(
                format!("{}search-target/{message}", self.prefix),
                serde_json::to_vec(&message)?,
            );
        }
        Ok(())
    }

    /// A physical page has at most 32 logical messages. No raw-operation or
    /// Realm-wide current scan is used, and one result retains at most two Events.
    pub(crate) async fn read_search_page(
        &self,
        actor: &arkret_sdk::ActorId,
        after: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<SearchPage> {
        let _lease = self.acquire_lease().await?;
        anyhow::ensure!(
            !self.is_poisoned(),
            "current pointer durability is unresolved"
        );
        let generation = self.generation.load(Ordering::Acquire);
        let prefix = format!("{}search-target/", self.prefix);
        anyhow::ensure!(
            after.is_none_or(|key| key.starts_with(&prefix)),
            "search cursor belongs to another account"
        );
        let entries = self.backend.scan(&prefix, None, after, 32).await?;
        let mut next = (entries.len() == 32).then(|| entries.last().unwrap().0.clone());
        let mut rows = Vec::new();
        let mut used = 0;
        let mut consumed = after.map(str::to_owned);
        for (key, bytes) in entries {
            let message: MessageId = serde_json::from_slice(&bytes)?;
            let Some(record) = self
                .latest::<SearchRecord>(&format!("{}search/{message}/", self.prefix), generation)
                .await?
            else {
                consumed = Some(key);
                continue;
            };
            let size = serde_json::to_vec(&record)?.len();
            if used + size > 8 * 1024 * 1024 && !rows.is_empty() {
                next = consumed;
                break;
            }
            consumed = Some(key);
            if size > 8 * 1024 * 1024 {
                continue;
            }
            used += size;
            let Some(create) = record.create else {
                continue;
            };
            if record.redacted || !self.search_visible(&create, actor, generation, now).await? {
                continue;
            }
            if let Some(revision) = record.revision {
                if revision.commit.stream_position <= create.commit.stream_position
                    || !self
                        .search_visible(&revision, actor, generation, now)
                        .await?
                {
                    continue;
                }
                rows.push(create);
                rows.push(revision);
            } else {
                rows.push(create);
            }
        }
        Ok(SearchPage {
            rows,
            next,
            generation,
        })
    }

    async fn search_visible(
        &self,
        full: &CommittedEventFullView,
        actor: &arkret_sdk::ActorId,
        generation: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        let realm = &full.event.realm_id;
        if full
            .event
            .verify_producer_proof_self_consistency(realm.digest_suite_code().digest_suite())
            .is_err()
        {
            return Ok(false);
        }
        if self
            .latest::<bool>(
                &format!("{}search-withheld/{}/", self.prefix, full.event.event_id),
                generation,
            )
            .await?
            .unwrap_or(false)
        {
            return Ok(false);
        }
        let progress = self.progress_at(realm.as_str(), generation).await?;
        if !progress_is_complete_cut(&progress, realm) {
            return Ok(false);
        }
        let Some(cut) = &progress.signed_snapshot else {
            return Ok(false);
        };
        let (Some(floors), Some(policies)) = (&cut.search_floor, &cut.search_policies) else {
            return Ok(false);
        };
        let Some(head) = cut
            .stream_heads
            .iter()
            .find(|head| head.stream_ref == full.commit.stream_ref)
        else {
            return Ok(false);
        };
        if head.stream_position < full.commit.stream_position
            || (head.stream_position == full.commit.stream_position
                && head.commit_id != full.commit.commit_id)
            || progress.observed_heads.iter().any(|known| {
                known.stream_ref == head.stream_ref
                    && (known.stream_position > head.stream_position
                        || (known.stream_position == head.stream_position
                            && known.commit_id != head.commit_id))
            })
            || !floors.stream_floors.iter().any(|floor| {
                floor.stream_ref == full.commit.stream_ref
                    && floor.oldest_position <= full.commit.stream_position
            })
        {
            return Ok(false);
        }
        let Some(parent) = self
            .ready_selector(
                realm.as_str(),
                &CurrentSelector::MemberState {
                    actor_id: actor.clone(),
                },
                generation,
            )
            .await?
        else {
            return Ok(false);
        };
        let Some(parent_revision) = parent.parent_membership_revision(realm, actor) else {
            return Ok(false);
        };
        if let arkret_sdk::ScopeRef::Circle { circle_id, .. } = &full.event.scope_ref {
            let Some(TypedCurrentRow::Value {
                source_stream_ref,
                value,
                ..
            }) = self
                .ready_selector(
                    realm.as_str(),
                    &CurrentSelector::CircleMemberState {
                        circle_id: circle_id.clone(),
                        member_actor_id: actor.clone(),
                    },
                    generation,
                )
                .await?
            else {
                return Ok(false);
            };
            let membership: arkret_wire::CircleMemberStateCurrent = serde_json::from_value(value)?;
            let TypedCurrentRow::Value {
                source_stream_ref: parent_stream,
                ..
            } = &parent;
            if source_stream_ref != full.commit.stream_ref
                || !membership.is_effective_under_parent(
                    realm,
                    parent_stream,
                    &parent_revision,
                    arkret_sdk::MembershipState::Join,
                )
            {
                return Ok(false);
            }
        }
        let create_id = match full.event.kind {
            EventKind::MessageCreate => full.event.event_id.clone(),
            _ => target(full)?.unwrap().event_id(),
        };
        let record = self
            .latest::<SearchRecord>(
                &format!(
                    "{}search/{}/",
                    self.prefix,
                    MessageId::from_event_id(&create_id)
                ),
                generation,
            )
            .await?;
        let Some(create) = record.and_then(|r| r.create) else {
            return Ok(false);
        };
        let payload: arkret_sdk::MessageCreatePayload =
            serde_json::from_value(serde_json::to_value(&create.event.payload)?)?;
        if payload.track_name != "discussion" {
            return Ok(false);
        }
        let Some(strand) = self
            .read_strand_at_generation(realm, &payload.strand_id, generation)
            .await?
        else {
            return Ok(false);
        };
        let strand_scope = match &strand.scope_circle_id {
            Some(circle_id) => arkret_sdk::ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: circle_id.clone(),
            },
            None => arkret_sdk::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
        };
        if strand_scope != full.event.scope_ref
            || strand.state != Some(arkret_wire::ObjectState::Active)
            || !strand
                .tracks
                .get("discussion")
                .is_some_and(|track| track.enabled != Some(false))
        {
            return Ok(false);
        }
        let mut active = Vec::new();
        for policy_id in policies {
            let Some(TypedCurrentRow::Value { value, .. }) = self
                .ready_selector(
                    realm.as_str(),
                    &CurrentSelector::Policy {
                        policy_id: policy_id.clone(),
                    },
                    generation,
                )
                .await?
            else {
                return Ok(false);
            };
            let policy: arkret_models_collaboration::governance::operation_wire::Policy =
                serde_json::from_value(value)?;
            // Unknown expiry semantics cannot release a retained plaintext.
            if policy.policy_kind == arkret_wire::PolicyKind::Retention {
                return Ok(false);
            }
            if matches!(
                policy.policy_kind,
                arkret_wire::PolicyKind::Access | arkret_wire::PolicyKind::Moderation
            ) {
                active.push(policy)
            }
        }
        let resource =
            arkret_sdk::WireResourceSelector::strand(realm.clone(), payload.strand_id.clone());
        let facts = arkret_policy::grant_evaluation::OperationFacts {
            strand_id: Some(payload.strand_id.to_string()),
            track: Some("discussion".into()),
            object_kind: Some("strand".into()),
            ..Default::default()
        };
        let operation = arkret_policy::grant_evaluation::AuthorizationOperation {
            actor,
            actions: &[arkret_sdk::CapabilityActionId::STRAND_READ],
            target: &resource,
            at: now,
            facts: &facts,
        };
        Ok(arkret_policy::signal_authorization::product_policies_allow(
            &active, &operation,
        ))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::test_support::committed_event::{
        FixtureStation, fixture_time, verified_realm_fixture_as,
    };

    async fn setup() -> (
        tempfile::TempDir,
        CurrentIndex,
        arkret_sdk::RealmStateSnapshot,
        Vec<CommittedEventFullView>,
        arkret_sdk::ActorId,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let index = super::super::tests::index(&directory.path().join("search.sqlite"), 0).await;
        let strand = arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [73; 32],
        ));
        let (bundle, _, originals) = verified_realm_fixture_as(
            "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"
                .parse()
                .unwrap(),
            vec![(
                "ak.message.create".into(),
                json!({"strand_id":strand,"track_name":"discussion", "content":{"kind":"ak.content.text","format":"plain","body":"exact original needle"}}),
            )],
            "alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        let create = &originals[0];
        let actor = create.event.actor_id.clone();
        let revision = CurrentRevision {
            commit_id: create.commit.commit_id.clone(),
            stream_position: create.commit.stream_position,
        };
        let mut snapshot = arkret_sdk::RealmStateSnapshot {
            snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
            realm_id: bundle.realm_id.clone(),
            governance_generation: 0,
            visible_stream_heads: vec![arkret_sdk::CommitStreamHead {
                stream_ref: create.commit.stream_ref.clone(),
                commit_id: create.commit.commit_id.clone(),
                stream_position: create.commit.stream_position,
            }],
            current_state_entries: vec![
                TypedCurrentRow::Value {
                    selector: CurrentSelector::MemberState {
                        actor_id: actor.clone(),
                    },
                    source_stream_ref: create.commit.stream_ref.clone(),
                    revision: revision.clone(),
                    value: json!({"membership":"join"}),
                },
                TypedCurrentRow::Value {
                    selector: CurrentSelector::Strand {
                        strand_id: strand.clone(),
                    },
                    source_stream_ref: create.commit.stream_ref.clone(),
                    revision,
                    value: serde_json::to_value(arkret_sdk::Strand::discussion(
                        strand,
                        bundle.realm_id.clone(),
                        "Search",
                        actor.clone(),
                    ))
                    .unwrap(),
                },
            ],
            retention_and_history_floor: arkret_sdk::RetentionAndHistoryFloor {
                history_access: arkret_sdk::HistoryAccess::SinceJoin,
                stream_floors: vec![arkret_sdk::StreamHistoryFloor {
                    stream_ref: create.commit.stream_ref.clone(),
                    oldest_position: 0,
                }],
            },
            created_at: fixture_time(10),
            signature: bundle.genesis_commit.signature,
        };
        FixtureStation::did_web().sign_snapshot(&mut snapshot);
        (directory, index, snapshot, originals, actor)
    }

    async fn stage(
        index: &CurrentIndex,
        snapshot: &arkret_sdk::RealmStateSnapshot,
        rows: Vec<arkret_sdk::CommittedEventView>,
        generation: u64,
    ) -> CurrentStage {
        let realm = snapshot.realm_id.to_string();
        let frame = serde_json::from_value(json!({"kind":"delta", "cursor":"ak:cursor:YQ", "realms":{&realm:{"current":{"realm_id":snapshot.realm_id,"governance_generation":0,"stream_heads":snapshot.visible_stream_heads,"entries":snapshot.current_state_entries},"committed_events":rows}}})).unwrap();
        index
            .stage_current_install(
                || Ok(generation),
                Some(&frame),
                None,
                &Default::default(),
                &BTreeMap::from([(realm, snapshot)]),
                &|| Ok(()),
                None,
                None,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn search_current_index_requires_publication_and_survives_reopen() {
        let (directory, index, snapshot, originals, actor) = setup().await;
        let rows = originals
            .iter()
            .cloned()
            .map(arkret_sdk::CommittedEventView::Full)
            .collect();
        let staged = stage(&index, &snapshot, rows, 0).await;
        // An abandoned stage must not publish candidates at the old account cut.
        drop(staged);
        assert!(
            index
                .read_search_page(&actor, None, fixture_time(20))
                .await
                .unwrap()
                .rows
                .is_empty()
        );
        stage(
            &index,
            &snapshot,
            originals
                .iter()
                .cloned()
                .map(arkret_sdk::CommittedEventView::Full)
                .collect(),
            0,
        )
        .await
        .finish();
        assert_eq!(
            index
                .read_search_page(&actor, None, fixture_time(20))
                .await
                .unwrap()
                .rows,
            originals
        );
        let reopened = super::super::tests::index(&directory.path().join("search.sqlite"), 1).await;
        assert_eq!(
            reopened
                .read_search_page(&actor, None, fixture_time(20))
                .await
                .unwrap()
                .rows,
            originals
        );
        let holder = super::super::super::LocalStateStore::default();
        let device: arkret_sdk::DeviceId = "ak:device:0196419b-0000-7000-8000-000000000001"
            .parse()
            .unwrap();
        let shown = crate::views::chat::model::chat_messages_from_search_originals(
            &originals,
            &holder,
            actor.as_account_id().unwrap(),
            &device,
        );
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].body, "exact original needle");
        assert_eq!(
            shown[0].crypto_state,
            crate::views::chat::model::MessageCryptoState::Plaintext
        );
        let other = arkret_sdk::ActorId::account(AccountId::new(
            actor.signing_principal_id().clone(),
            "ak:did_core:web:other.example".parse().unwrap(),
        ));
        assert!(
            reopened
                .read_search_page(&other, None, fixture_time(20))
                .await
                .unwrap()
                .rows
                .is_empty()
        );
    }

    #[tokio::test]
    async fn search_current_index_revocation_floor_and_withheld_suppress_originals() {
        for scenario in [
            "leave",
            "floor",
            "withheld",
            "wrong_scope",
            "missing_strand",
        ] {
            let (_directory, index, mut snapshot, originals, actor) = setup().await;
            stage(
                &index,
                &snapshot,
                originals
                    .iter()
                    .cloned()
                    .map(arkret_sdk::CommittedEventView::Full)
                    .collect(),
                0,
            )
            .await
            .finish();
            match scenario {
                "leave" => {
                    let TypedCurrentRow::Value { value, .. } =
                        &mut snapshot.current_state_entries[0];
                    *value = json!({"membership":"leave"});
                }
                "floor" => {
                    snapshot.retention_and_history_floor.stream_floors[0].oldest_position =
                        originals[0].commit.stream_position + 1
                }
                "wrong_scope" => {
                    let TypedCurrentRow::Value { value, .. } =
                        &mut snapshot.current_state_entries[1];
                    value["scope_circle_id"] = json!(arkret_sdk::CircleId::from_event_id(
                        &originals[0].event.event_id
                    ));
                }
                "missing_strand" => {
                    snapshot.current_state_entries.pop();
                }
                _ => {}
            }
            // Fresh signed-cut changes must use a newer row coordinate.
            for row in &mut snapshot.current_state_entries {
                let TypedCurrentRow::Value { revision, .. } = row;
                revision.stream_position += 1;
                revision.commit_id = arkret_sdk::RealmCommitId::from_digest([83; 32]);
            }
            snapshot.visible_stream_heads[0].stream_position += 1;
            snapshot.visible_stream_heads[0].commit_id =
                arkret_sdk::RealmCommitId::from_digest([83; 32]);
            FixtureStation::did_web().sign_snapshot(&mut snapshot);
            let rows = if scenario == "withheld" {
                vec![serde_json::from_value(json!({"commit":originals[0].commit,"event_disclosure":{"status":"withheld"}})).unwrap()]
            } else {
                vec![]
            };
            stage(&index, &snapshot, rows, 1).await.finish();
            assert!(
                index
                    .read_search_page(&actor, None, fixture_time(20))
                    .await
                    .map(|p| p.rows.is_empty())
                    .unwrap_or(true),
                "{scenario}"
            );
        }
    }

    #[tokio::test]
    async fn search_current_index_uses_latest_committed_revision_and_redaction() {
        let (_directory, index, mut snapshot, originals, actor) = setup().await;
        stage(
            &index,
            &snapshot,
            originals
                .iter()
                .cloned()
                .map(arkret_sdk::CommittedEventView::Full)
                .collect(),
            0,
        )
        .await
        .finish();
        let create = &originals[0];
        let message = MessageId::from_event_id(&create.event.event_id);
        let create_payload = serde_json::to_value(&create.event.payload).unwrap();
        let revise = json!({"message_id":message,"content":{"kind":"ak.content.text","format":"plain","body":"latest replacement needle"}});
        let redact = json!({"message_id":message});
        let (_, _, later) = verified_realm_fixture_as(
            "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"
                .parse()
                .unwrap(),
            vec![
                ("ak.message.create".into(), create_payload),
                ("ak.message.revise".into(), revise),
                ("ak.message.redact".into(), redact),
            ],
            "alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        assert_eq!(later[0], *create);
        let holder = super::super::super::LocalStateStore::default();
        let device = "ak:device:0196419b-0000-7000-8000-000000000001"
            .parse()
            .unwrap();
        for (generation, row) in later.iter().enumerate().skip(1) {
            snapshot.visible_stream_heads[0].stream_position = row.commit.stream_position;
            snapshot.visible_stream_heads[0].commit_id = row.commit.commit_id.clone();
            FixtureStation::did_web().sign_snapshot(&mut snapshot);
            stage(
                &index,
                &snapshot,
                vec![arkret_sdk::CommittedEventView::Full(row.clone())],
                generation as u64,
            )
            .await
            .finish();
            let page = index
                .read_search_page(&actor, None, fixture_time(20))
                .await
                .unwrap();
            if row.event.kind == EventKind::MessageRevise {
                assert_eq!(page.rows, vec![create.clone(), row.clone()]);
                let shown = crate::views::chat::model::chat_messages_from_search_originals(
                    &page.rows,
                    &holder,
                    actor.as_account_id().unwrap(),
                    &device,
                );
                assert_eq!(shown.len(), 1);
                assert_eq!(shown[0].body, "latest replacement needle");
                // A corrupted latest original must not fall back to the old
                // create body merely because that older proof still verifies.
                let key = format!(
                    "{}search/{message}/{}",
                    index.prefix,
                    version(generation as u64 + 1)
                );
                let bytes = index.backend.get(&key).await.unwrap().unwrap();
                let mut corrupt: SearchRecord = serde_json::from_slice(&bytes).unwrap();
                corrupt
                    .revision
                    .as_mut()
                    .unwrap()
                    .event
                    .payload
                    .get_mut("content")
                    .unwrap()["body"] = json!("tampered needle");
                index
                    .backend
                    .apply(
                        vec![],
                        vec![(key.clone(), serde_json::to_vec(&corrupt).unwrap())],
                    )
                    .await
                    .unwrap();
                assert!(
                    index
                        .read_search_page(&actor, None, fixture_time(20))
                        .await
                        .unwrap()
                        .rows
                        .is_empty()
                );
                index
                    .backend
                    .apply(vec![], vec![(key, bytes)])
                    .await
                    .unwrap();
            } else {
                assert!(page.rows.is_empty());
            }
        }
    }
}
