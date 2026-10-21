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
        self.search_session_valid_until(account, device, chrono::Utc::now())
            .is_some()
    }

    /// A displayed result cannot outlive any part of its current holder evidence.
    pub(crate) fn search_session_valid_until(
        &self,
        account: &AccountId,
        device: &arkret_sdk::DeviceId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        if self.active_authority().as_ref() != Some(account)
            || self.current_reset_required()
            || self.persist_error().is_some()
        {
            return None;
        }
        self.with_unoverlaid_account_fields(|state| {
            let grant = state.session_grant.as_ref()?;
            let authority = state.device_authoring_authority.as_ref()?;
            let projection = &authority.device_projection;
            let expiry = grant.grant_expires_at?.min(projection.expires_at).min(
                projection
                    .authorization_window
                    .expires_at
                    .unwrap_or(projection.expires_at),
            );
            (grant.account_id == *account
                && grant.device_id == *device
                && authority.account_id == *account
                && authority.device_id == *device
                && projection.device_status.is_active()
                && projection.attested_at <= now
                && projection.authorization_window.not_before <= now
                && expiry > now
                && crate::identity::authoring_generation::cached_principal_authoring_generation(
                    account,
                    device.as_str(),
                )
                .is_none_or(|generation| generation == authority.authoring_generation))
            .then_some(expiry)
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SearchRecord {
    create: Option<CommittedEventFullView>,
    revision: Option<CommittedEventFullView>,
    redacted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redaction_stream: Option<arkret_sdk::CommitStreamRef>,
}

// Keep the existing boolean disclosure bytes and physical key. Event cropping
// is terminal for that exact signed source, unlike a temporary withheld read.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum SearchDisclosure {
    Withheld(bool),
    Redacted {
        source_stream_ref: arkret_sdk::CommitStreamRef,
    },
}

pub(crate) struct SearchPage {
    pub rows: Vec<CommittedEventFullView>,
    pub next: Option<String>,
    pub generation: u64,
    pub recheck_at: Option<chrono::DateTime<chrono::Utc>>,
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
    async fn stage_search_disclosure(
        &self,
        event: &arkret_sdk::EventId,
        disclosure: SearchDisclosure,
        committed: u64,
        suffix: &str,
        writes: &mut BTreeMap<String, Vec<u8>>,
    ) -> anyhow::Result<()> {
        let prefix = format!("{}search-withheld/{event}/", self.prefix);
        let key = format!("{prefix}{suffix}");
        let staged: Option<SearchDisclosure> = writes
            .get(&key)
            .map(|bytes| serde_json::from_slice(bytes))
            .transpose()?;
        let previous: Option<SearchDisclosure> = match staged.as_ref() {
            Some(value) => Some(value.clone()),
            None => self.latest(&prefix, committed).await?,
        };
        let disclosure = match (previous, disclosure) {
            (
                Some(SearchDisclosure::Redacted { source_stream_ref }),
                SearchDisclosure::Redacted {
                    source_stream_ref: incoming,
                },
            ) => {
                anyhow::ensure!(
                    source_stream_ref == incoming,
                    "Event crop crosses its original stream"
                );
                SearchDisclosure::Redacted { source_stream_ref }
            }
            (Some(terminal @ SearchDisclosure::Redacted { .. }), _) => terminal,
            (_, terminal @ SearchDisclosure::Redacted { .. }) => terminal,
            (_, SearchDisclosure::Withheld(withheld)) => SearchDisclosure::Withheld(
                withheld || matches!(staged, Some(SearchDisclosure::Withheld(true))),
            ),
        };
        writes.insert(key, serde_json::to_vec(&disclosure)?);
        Ok(())
    }

    pub(super) async fn stage_search_rows(
        &self,
        incoming: &arkret_sdk::sync::RealmSyncEntry,
        snapshot: Option<&arkret_sdk::RealmStateSnapshot>,
        committed: u64,
        suffix: &str,
        writes: &mut BTreeMap<String, Vec<u8>>,
        targets: &mut BTreeMap<String, Vec<u8>>,
    ) -> anyhow::Result<()> {
        for view in incoming.committed_events.iter().flatten() {
            let arkret_sdk::CommittedEventView::Full(full) = view else {
                self.stage_search_disclosure(
                    &view.commit().event_ref,
                    SearchDisclosure::Withheld(true),
                    committed,
                    suffix,
                    writes,
                )
                .await?;
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
            // Disclosure is a current read outcome, not a terminal redaction.
            // A newly verified Full can replace an older withheld outcome for
            // this exact Event. Within one installation, withheld wins in
            // either input order. Publication shares the candidate transaction;
            // the current authorization and revision gates still apply below.
            self.stage_search_disclosure(
                &full.event.event_id,
                SearchDisclosure::Withheld(false),
                committed,
                suffix,
                writes,
            )
            .await?;
            let prefix = format!("{}search/{}/", self.prefix, message);
            let key = format!("{prefix}{suffix}");
            let mut record: SearchRecord = match writes.get(&key) {
                Some(bytes) => serde_json::from_slice(bytes)?,
                None => self.latest(&prefix, committed).await?.unwrap_or_default(),
            };
            anyhow::ensure!(
                record
                    .redaction_stream
                    .as_ref()
                    .is_none_or(|stream| stream == &full.commit.stream_ref),
                "search original crosses a terminal redaction scope"
            );
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
                EventKind::MessageRedact => {
                    record.redacted = true;
                    record.redaction_stream = Some(full.commit.stream_ref.clone());
                }
                _ => unreachable!(),
            }
            if record.redacted {
                record.create = None;
                record.revision = None;
            }
            writes.insert(key, serde_json::to_vec(&record)?);
            targets.insert(
                format!("{}search-target/{message}", self.prefix),
                serde_json::to_vec(&message)?,
            );
        }
        // A snapshot may disclose the terminal current without returning the
        // redact Event. Fold even unchanged snapshot rows: the candidate may
        // have arrived later than its already installed redaction evidence.
        let rows = snapshot
            .map(|snapshot| snapshot.current_state_entries.as_slice())
            .or_else(|| {
                incoming
                    .current
                    .as_ref()
                    .map(|current| current.entries.as_slice())
            })
            .unwrap_or_default();
        for row in rows {
            let TypedCurrentRow::Value {
                selector: CurrentSelector::ObjectRedaction { target_ref },
                source_stream_ref,
                value,
                ..
            } = row
            else {
                continue;
            };
            let event = target_ref.parse::<arkret_sdk::EventId>().ok();
            let message = MessageId::new(target_ref.as_str()).ok();
            if event.is_none() && message.is_none() {
                continue;
            }
            let redaction: arkret_models_collaboration::events_payloads::redaction::ObjectRedactionCurrentValue = serde_json::from_value(value.clone())?;
            redaction.validate_for_subject(target_ref)?;
            if let Some(event) = event {
                self.stage_search_disclosure(
                    &event,
                    SearchDisclosure::Redacted {
                        source_stream_ref: source_stream_ref.clone(),
                    },
                    committed,
                    suffix,
                    writes,
                )
                .await?;
                continue;
            }
            // Event spellings must never become terminal Message state.
            let message = message.unwrap();
            let prefix = format!("{}search/{message}/", self.prefix);
            let key = format!("{prefix}{suffix}");
            let mut record: SearchRecord = match writes.get(&key) {
                Some(bytes) => serde_json::from_slice(bytes)?,
                None => self.latest(&prefix, committed).await?.unwrap_or_default(),
            };
            anyhow::ensure!(
                record
                    .create
                    .as_ref()
                    .is_none_or(|create| &create.commit.stream_ref == source_stream_ref)
                    && record
                        .revision
                        .as_ref()
                        .is_none_or(|revision| &revision.commit.stream_ref == source_stream_ref)
                    && record
                        .redaction_stream
                        .as_ref()
                        .is_none_or(|stream| stream == source_stream_ref),
                "search current redaction crosses the target security scope"
            );
            record.redacted = true;
            record.redaction_stream = Some(source_stream_ref.clone());
            record.create = None;
            record.revision = None;
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
        let mut recheck_at = None;
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
            // A disclosed current can advance before its signed original is
            // delivered. Never promote the cached prefix to the current body.
            let carrier = record.revision.as_ref().unwrap_or(&create);
            if record.redacted
                || !self
                    .search_revision_is_current(&message, carrier, generation)
                    .await?
                || !self
                    .search_visible(&create, actor, generation, now, &mut recheck_at)
                    .await?
            {
                continue;
            }
            if let Some(revision) = record.revision {
                if revision.commit.stream_position <= create.commit.stream_position
                    || !self
                        .search_visible(&revision, actor, generation, now, &mut recheck_at)
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
            recheck_at,
        })
    }

    async fn search_revision_is_current(
        &self,
        message: &MessageId,
        carrier: &CommittedEventFullView,
        generation: u64,
    ) -> anyhow::Result<bool> {
        let Some(TypedCurrentRow::Value {
            source_stream_ref,
            revision,
            value,
            ..
        }) = self
            .ready_selector(
                carrier.event.realm_id.as_str(),
                &CurrentSelector::MessageRevision {
                    message_id: message.clone(),
                },
                generation,
            )
            .await?
        else {
            return Ok(false);
        };
        Ok(source_stream_ref == carrier.commit.stream_ref
            && revision.commit_id == carrier.commit.commit_id
            && revision.stream_position == carrier.commit.stream_position
            && value == serde_json::to_value(&carrier.event.payload)?)
    }

    async fn search_visible(
        &self,
        full: &CommittedEventFullView,
        actor: &arkret_sdk::ActorId,
        generation: u64,
        now: chrono::DateTime<chrono::Utc>,
        recheck_at: &mut Option<chrono::DateTime<chrono::Utc>>,
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
            .latest::<SearchDisclosure>(
                &format!("{}search-withheld/{}/", self.prefix, full.event.event_id),
                generation,
            )
            .await?
            .is_some_and(|disclosure| !matches!(disclosure, SearchDisclosure::Withheld(false)))
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
        // Recheck the installed current as well as the materialized terminal
        // bit, including candidates cached before current-redaction folding.
        let message = match full.event.kind {
            EventKind::MessageCreate => MessageId::from_event_id(&full.event.event_id),
            _ => target(full)?.unwrap(),
        };
        // The Event spelling is an independent field-cropping assertion, not
        // the terminal Message state. An intact cached signed Event cannot be
        // presented as a cropped Full original. Omit that candidate just like
        // the Station's canonical-byte disclosure gate, without manufacturing
        // a Message tombstone or rewriting the producer's signed payload.
        for subject in [message.to_string(), full.event.event_id.to_string()] {
            if let Some(TypedCurrentRow::Value { value, .. }) = self
                .ready_selector(
                    realm.as_str(),
                    &CurrentSelector::ObjectRedaction {
                        target_ref: subject.clone(),
                    },
                    generation,
                )
                .await?
            {
                let redaction: arkret_models_collaboration::events_payloads::redaction::ObjectRedactionCurrentValue = serde_json::from_value(value)?;
                redaction.validate_for_subject(&subject)?;
                return Ok(false);
            }
        }
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
                    &CurrentSelector::Circle {
                        circle_id: circle_id.clone(),
                    },
                    generation,
                )
                .await?
            else {
                return Ok(false);
            };
            let circle: arkret_models_collaboration::governance::circle::Circle =
                serde_json::from_value(value)?;
            // Archive preserves historical reads; tombstone makes the scope
            // unavailable even while its canonical member row remains join.
            if circle.id.as_ref() != Some(circle_id)
                || circle.realm_id != *realm
                || circle.schema != arkret_wire::SchemaId::CIRCLE_V1
                || source_stream_ref
                    != (arkret_sdk::CommitStreamRef::Realm {
                        realm_id: realm.clone(),
                    })
                || circle.state
                    == arkret_models_collaboration::governance::circle::CircleState::Tombstoned
            {
                return Ok(false);
            }
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
            if matches!(
                policy.policy_kind,
                arkret_wire::PolicyKind::Access
                    | arkret_wire::PolicyKind::Moderation
                    | arkret_wire::PolicyKind::Retention
            ) {
                // These are Policy validity boundaries, never message TTLs.
                // Include inactive deny policies so a displayed body is
                // rechecked when they become effective without a new cut.
                for boundary in [
                    Some(policy.created_at),
                    policy.not_before,
                    policy.expires_at,
                ]
                .into_iter()
                .flatten()
                .filter(|boundary| *boundary > now)
                {
                    *recheck_at = Some(recheck_at.map_or(boundary, |held| held.min(boundary)));
                }
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

    #[cfg(target_arch = "wasm32")]
    pub(super) async fn search_originals_present(
        &self,
        message: &MessageId,
    ) -> anyhow::Result<bool> {
        let _lease = self.acquire_lease().await?;
        let record: Option<SearchRecord> = self
            .latest(
                &format!("{}search/{message}/", self.prefix),
                self.generation.load(Ordering::Acquire),
            )
            .await?;
        Ok(record.is_some_and(|record| record.create.is_some() || record.revision.is_some()))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;
    use crate::test_support::committed_event::{
        FixtureStation, fixture_time, verified_realm_fixture_as,
    };

    mod circle_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/search_circle.rs"
        ));
    }

    async fn stage_circle_fixture(
        index: &CurrentIndex,
        fixture: &circle_fixture::Fixture,
        originals: bool,
        generation: u64,
    ) -> CurrentStage {
        let frame = serde_json::from_str(&fixture.frame(originals)).unwrap();
        index
            .stage_current_install(
                || Ok(generation),
                Some(&frame),
                None,
                &Default::default(),
                &BTreeMap::from([(fixture.snapshot.realm_id.to_string(), &fixture.snapshot)]),
                &|| Ok(()),
                None,
                None,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn search_retention_policy_and_validity_boundaries_use_the_same_durable_cut() {
        for (scenario, fixture, checks) in circle_fixture::policy_cases() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("retention-policy.sqlite");
            let index = super::super::tests::index(&path, 0).await;
            stage_circle_fixture(&index, &fixture, true, 0)
                .await
                .finish();
            drop(index);
            for check in checks {
                let reopened = super::super::tests::index(&path, 1).await;
                let page = reopened
                    .read_search_page(&fixture.actor, None, check.now)
                    .await
                    .unwrap();
                assert_eq!(
                    page.rows,
                    if check.visible {
                        vec![fixture.message.clone()]
                    } else {
                        vec![]
                    },
                    "{scenario} {}",
                    check.now
                );
                assert_eq!(
                    page.recheck_at, check.recheck_at,
                    "{scenario} {}",
                    check.now
                );
                assert_eq!(page.generation, 1);
            }
        }
    }

    #[tokio::test]
    async fn search_event_redaction_never_releases_cached_full_or_creates_a_message_tombstone() {
        for (scenario, steps) in circle_fixture::event_redaction_cases() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("event-redaction.sqlite");
            let fixture = circle_fixture::Fixture::new();
            for (generation, step) in steps.into_iter().enumerate() {
                let index = super::super::tests::index(&path, generation as u64).await;
                let frame = serde_json::from_str(&step.frame).unwrap();
                let snapshot: arkret_sdk::RealmStateSnapshot =
                    serde_json::from_str(&step.snapshot).unwrap();
                let mut stage = index
                    .stage_current_install(
                        || Ok(generation as u64),
                        Some(&frame),
                        None,
                        &Default::default(),
                        &BTreeMap::from([(snapshot.realm_id.to_string(), &snapshot)]),
                        &|| Ok(()),
                        None,
                        None,
                    )
                    .await
                    .unwrap();
                if generation == 1 {
                    // Abandoning the crop must leave the durable cut readable.
                    drop(stage);
                    assert_eq!(
                        index
                            .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                            .await
                            .unwrap()
                            .rows
                            .len(),
                        if scenario == "redaction_first" {
                            0
                        } else if matches!(scenario, "revision" | "revised_create") {
                            2
                        } else {
                            1
                        }
                    );
                    stage = self::stage(&index, &snapshot, vec![], generation as u64).await;
                }
                stage.finish();
                assert_eq!(
                    index
                        .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                        .await
                        .unwrap()
                        .rows,
                    step.expected,
                    "{scenario} {generation}"
                );
                let message = MessageId::from_event_id(&fixture.message.event.event_id);
                let record: Option<SearchRecord> = index
                    .latest(
                        &format!("{}search/{message}/", index.prefix),
                        generation as u64 + 1,
                    )
                    .await
                    .unwrap();
                assert!(
                    !record.as_ref().is_some_and(|record| record.redacted),
                    "Event crop is not Message terminal state"
                );
                drop(index);
                let reopened = super::super::tests::index(&path, generation as u64 + 1).await;
                assert_eq!(
                    reopened
                        .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                        .await
                        .unwrap()
                        .rows,
                    step.expected,
                    "cold {scenario} {generation}"
                );
            }
        }
    }

    #[tokio::test]
    async fn search_disclosure_backfill_recovers_exact_original_without_reopening_other_gates() {
        for (scenario, steps) in circle_fixture::disclosure_cases() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("disclosure.sqlite");
            let actor = circle_fixture::Fixture::new().actor;
            for (generation, step) in steps.into_iter().enumerate() {
                let index = super::super::tests::index(&path, generation as u64).await;
                let frame = serde_json::from_str(&step.frame).unwrap();
                let snapshot: arkret_sdk::RealmStateSnapshot =
                    serde_json::from_str(&step.snapshot).unwrap();
                index
                    .stage_current_install(
                        || Ok(generation as u64),
                        Some(&frame),
                        None,
                        &Default::default(),
                        &BTreeMap::from([(snapshot.realm_id.to_string(), &snapshot)]),
                        &|| Ok(()),
                        None,
                        None,
                    )
                    .await
                    .unwrap()
                    .finish();
                assert_eq!(
                    index
                        .read_search_page(&actor, None, circle_fixture::at(20))
                        .await
                        .unwrap()
                        .rows,
                    step.expected,
                    "{scenario} {generation}"
                );
                drop(index);
                let reopened = super::super::tests::index(&path, generation as u64 + 1).await;
                assert_eq!(
                    reopened
                        .read_search_page(&actor, None, circle_fixture::at(20))
                        .await
                        .unwrap()
                        .rows,
                    step.expected,
                    "cold {scenario} {generation}"
                );
            }
        }
    }

    #[tokio::test]
    async fn search_revision_current_advance_waits_for_exact_original_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("revision.sqlite");
        let index = super::super::tests::index(&path, 0).await;
        let mut fixture = circle_fixture::Fixture::new();
        stage_circle_fixture(&index, &fixture, true, 0)
            .await
            .finish();
        let read = || index.read_search_page(&fixture.actor, None, circle_fixture::at(20));
        assert_eq!(read().await.unwrap().rows, vec![fixture.message.clone()]);
        fixture.revise_message();
        let staged = stage_circle_fixture(&index, &fixture, false, 1).await;
        drop(staged);
        assert_eq!(
            index
                .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                .await
                .unwrap()
                .rows,
            vec![fixture.message.clone()],
            "abandoned current must not affect the published body"
        );
        stage_circle_fixture(&index, &fixture, false, 1)
            .await
            .finish();
        assert!(
            index
                .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                .await
                .unwrap()
                .rows
                .is_empty()
        );
        // Replaying the old create cannot fill a newer revision's missing body.
        let revision = fixture.originals.pop().unwrap();
        stage_circle_fixture(&index, &fixture, true, 2)
            .await
            .finish();
        drop(index);
        let reopened = super::super::tests::index(&path, 3).await;
        assert!(
            reopened
                .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                .await
                .unwrap()
                .rows
                .is_empty()
        );
        fixture.originals.push(revision.clone());
        stage_circle_fixture(&reopened, &fixture, true, 3)
            .await
            .finish();
        let expected = vec![fixture.message.clone(), revision];
        assert_eq!(
            reopened
                .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                .await
                .unwrap()
                .rows,
            expected
        );
        drop(reopened);
        let recovered = super::super::tests::index(&path, 4).await;
        assert_eq!(
            recovered
                .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                .await
                .unwrap()
                .rows,
            expected
        );
    }

    #[tokio::test]
    async fn search_revision_current_requires_exact_carrier_evidence() {
        for revised in [false, true] {
            for scenario in [
                "missing",
                "wrong_source",
                "wrong_commit",
                "wrong_position",
                "wrong_payload",
                "wrong_target",
                "older_current",
            ] {
                if !revised && scenario == "older_current" {
                    continue;
                }
                let directory = tempfile::tempdir().unwrap();
                let index =
                    super::super::tests::index(&directory.path().join("revision.sqlite"), 0).await;
                let mut fixture = circle_fixture::Fixture::new();
                if revised {
                    fixture.revise_message();
                }
                fixture.change_revision(scenario);
                let frame = serde_json::from_str(&fixture.frame(true)).unwrap();
                let staged = index
                    .stage_current_install(
                        || Ok(0),
                        Some(&frame),
                        None,
                        &Default::default(),
                        &BTreeMap::from([(
                            fixture.snapshot.realm_id.to_string(),
                            &fixture.snapshot,
                        )]),
                        &|| Ok(()),
                        None,
                        None,
                    )
                    .await;
                if let Ok(staged) = staged {
                    staged.finish();
                }
                assert!(
                    index
                        .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                        .await
                        .unwrap()
                        .rows
                        .is_empty(),
                    "{revised} {scenario}"
                );
            }
        }
    }

    #[tokio::test]
    async fn search_current_message_redaction_is_terminal_without_history_and_scrubs_candidates() {
        for scenario in [
            "redaction_only",
            "redaction_first",
            "other_message",
            "revised",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("current-redaction.sqlite");
            let index = super::super::tests::index(&path, 0).await;
            let mut fixture = circle_fixture::Fixture::new();
            if scenario == "revised" {
                fixture.revise_message();
            }
            let message = MessageId::from_event_id(&fixture.message.event.event_id);
            stage_circle_fixture(&index, &fixture, scenario != "redaction_first", 0)
                .await
                .finish();
            let target = if scenario == "other_message" {
                MessageId::from_event_id(&arkret_sdk::EventId::from_digest(
                    arkret_sdk::DigestSuite::Sha256,
                    [101; 32],
                ))
            } else {
                message.clone()
            };
            fixture.redact_message_current(target.as_str());
            // An abandoned stage must not redact the still committed cut.
            drop(stage_circle_fixture(&index, &fixture, false, 1).await);
            assert_eq!(
                index
                    .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                    .await
                    .unwrap()
                    .rows
                    .len(),
                if scenario == "revised" {
                    2
                } else {
                    usize::from(scenario != "redaction_first")
                }
            );
            stage_circle_fixture(&index, &fixture, false, 1)
                .await
                .finish();
            // A late/replayed original cannot undo a current-only terminal fact.
            stage_circle_fixture(&index, &fixture, true, 2)
                .await
                .finish();
            let expected = if scenario == "other_message" {
                vec![fixture.message.clone()]
            } else {
                vec![]
            };
            assert_eq!(
                index
                    .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                    .await
                    .unwrap()
                    .rows,
                expected,
                "{scenario}"
            );
            let record: SearchRecord = index
                .latest(&format!("{}search/{message}/", index.prefix), 3)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                record.create.is_some() || record.revision.is_some(),
                scenario == "other_message",
                "retained body {scenario}"
            );
            // Changing disclosure must not resurrect a known terminal Message.
            fixture
                .snapshot
                .current_state_entries
                .retain(|row| !matches!(selector_of(row), CurrentSelector::ObjectRedaction { .. }));
            fixture.snapshot.created_at = circle_fixture::at(13);
            circle_fixture::seal(&mut fixture.snapshot);
            stage_circle_fixture(&index, &fixture, true, 3)
                .await
                .finish();
            drop(index);
            let reopened = super::super::tests::index(&path, 4).await;
            assert_eq!(
                reopened
                    .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                    .await
                    .unwrap()
                    .rows,
                expected,
                "cold {scenario}"
            );
        }
    }

    #[tokio::test]
    async fn search_current_redaction_masks_unfolded_legacy_candidates() {
        let directory = tempfile::tempdir().unwrap();
        let index =
            super::super::tests::index(&directory.path().join("legacy-redaction.sqlite"), 0).await;
        let mut fixture = circle_fixture::Fixture::new();
        stage_circle_fixture(&index, &fixture, true, 0)
            .await
            .finish();
        let message = MessageId::from_event_id(&fixture.message.event.event_id);
        let prefix = format!("{}search/{message}/", index.prefix);
        let legacy: SearchRecord = index.latest(&prefix, 1).await.unwrap().unwrap();
        fixture.redact_message_current(message.as_str());
        stage_circle_fixture(&index, &fixture, false, 1)
            .await
            .finish();
        // The previous production version installed the current row but left
        // this exact original cached. Reading must reject it without a rewrite.
        index
            .backend
            .apply(
                vec![],
                vec![(
                    format!("{prefix}{}", version(2)),
                    serde_json::to_vec(&legacy).unwrap(),
                )],
            )
            .await
            .unwrap();
        assert!(
            index
                .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                .await
                .unwrap()
                .rows
                .is_empty()
        );
    }

    #[tokio::test]
    async fn search_current_message_redaction_rejects_bad_evidence_without_publication() {
        for scenario in ["empty", "wrong_subject", "wrong_stream"] {
            let directory = tempfile::tempdir().unwrap();
            let index =
                super::super::tests::index(&directory.path().join("invalid-redaction.sqlite"), 0)
                    .await;
            let mut fixture = circle_fixture::Fixture::new();
            stage_circle_fixture(&index, &fixture, true, 0)
                .await
                .finish();
            let target = MessageId::from_event_id(&fixture.message.event.event_id);
            fixture.redact_message_current(target.as_str());
            let TypedCurrentRow::Value {
                value,
                source_stream_ref,
                revision,
                ..
            } = fixture.snapshot.current_state_entries.last_mut().unwrap();
            match scenario {
                "empty" => value["assertions"] = json!([]),
                "wrong_subject" => {
                    value["assertions"][0]["value"]["message_id"] =
                        json!(MessageId::from_event_id(&arkret_sdk::EventId::from_digest(
                            arkret_sdk::DigestSuite::Sha256,
                            [102; 32]
                        )))
                }
                _ => {
                    let head = &fixture.snapshot.visible_stream_heads[0];
                    *source_stream_ref = head.stream_ref.clone();
                    *revision = CurrentRevision {
                        commit_id: head.commit_id.clone(),
                        stream_position: head.stream_position,
                    };
                }
            }
            circle_fixture::seal(&mut fixture.snapshot);
            let frame = serde_json::from_str(&fixture.frame(false)).unwrap();
            assert!(
                index
                    .stage_current_install(
                        || Ok(1),
                        Some(&frame),
                        None,
                        &Default::default(),
                        &BTreeMap::from([(
                            fixture.snapshot.realm_id.to_string(),
                            &fixture.snapshot
                        )]),
                        &|| Ok(()),
                        None,
                        None
                    )
                    .await
                    .is_err(),
                "{scenario}"
            );
            assert_eq!(index.generation.load(Ordering::Acquire), 1);
            assert_eq!(
                index
                    .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                    .await
                    .unwrap()
                    .rows,
                vec![fixture.message],
                "old cut {scenario}"
            );
        }
    }

    #[tokio::test]
    async fn search_circle_current_scope_survives_archive_but_not_terminal_or_missing_evidence() {
        for scenario in circle_fixture::SCENARIOS {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("circle-search.sqlite");
            let index = super::super::tests::index(&path, 0).await;
            let mut fixture = circle_fixture::Fixture::new();
            // Source changes on an existing row are rejected at installation.
            // A first cut must also refuse to read a misbound Circle source.
            if scenario == "wrong_source" {
                fixture.change(scenario);
            }
            let frame: arkret_sdk::sync::AccountSubscribeFrame =
                serde_json::from_str(&fixture.frame(true)).unwrap();
            let realm = fixture.snapshot.realm_id.to_string();
            let staged = index
                .stage_current_install(
                    || Ok(0),
                    Some(&frame),
                    None,
                    &Default::default(),
                    &BTreeMap::from([(realm.clone(), &fixture.snapshot)]),
                    &|| Ok(()),
                    None,
                    None,
                )
                .await
                .unwrap();
            staged.finish();
            let initial = if scenario == "wrong_source" {
                vec![]
            } else {
                vec![fixture.message.clone()]
            };
            assert_eq!(
                index
                    .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                    .await
                    .unwrap()
                    .rows,
                initial,
                "initial {scenario}"
            );
            if scenario == "wrong_source" {
                drop(index);
                let reopened = super::super::tests::index(&path, 1).await;
                assert!(
                    reopened
                        .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                        .await
                        .unwrap()
                        .rows
                        .is_empty()
                );
                continue;
            }
            fixture.change(scenario);
            let frame = serde_json::from_str(&fixture.frame(false)).unwrap();
            index
                .stage_current_install(
                    || Ok(1),
                    Some(&frame),
                    None,
                    &Default::default(),
                    &BTreeMap::from([(realm, &fixture.snapshot)]),
                    &|| Ok(()),
                    None,
                    None,
                )
                .await
                .unwrap()
                .finish();
            let expected = if scenario == "archived" {
                vec![fixture.message.clone()]
            } else {
                vec![]
            };
            assert_eq!(
                index
                    .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                    .await
                    .unwrap()
                    .rows,
                expected,
                "live {scenario}"
            );
            drop(index);
            let reopened = super::super::tests::index(&path, 2).await;
            assert_eq!(
                reopened
                    .read_search_page(&fixture.actor, None, circle_fixture::at(20))
                    .await
                    .unwrap()
                    .rows,
                expected,
                "reopened {scenario}"
            );
        }
    }

    pub(crate) async fn authorized_store() -> (
        tempfile::TempDir,
        crate::state::LocalStateStore,
        crate::config::ActiveAccountContext,
        CommittedEventFullView,
    ) {
        let (directory, _, snapshot, originals, actor) = setup().await;
        let account = crate::test_support::AccountFixture::new("did:web:alice.example")
            .station(actor.as_account_id().unwrap().station_id.as_str())
            .device("ak:device:0196419b-0000-7000-8000-000000000001")
            .build();
        let mut store =
            crate::state::LocalStateStore::with_path(directory.path().join("holder.json"));
        store.switch_active_account(&account).unwrap();
        store.set_current_reset_required(false);
        let now = chrono::Utc::now();
        store.set_session_grant(Some(crate::state::PersistedSessionGrant {
            grant_jwt: "fixture-grant".into(),
            session_private_key_pem: String::new(),
            grant_id: "fixture-grant-id".into(),
            audience_id: account.authority.station_id.clone(),
            granted_scope: Vec::new(),
            account_id: account.authority.clone(),
            device_id: account.device_id.clone(),
            station_url: account.server_url.clone(),
            grant_expires_at: Some(now + chrono::Duration::hours(1)),
            stored_at: now,
        }));
        store
            .set_device_authoring_authority(Some(crate::state::PersistedDeviceAuthoringAuthority {
            account_id: account.authority.clone(),
            device_id: account.device_id.clone(),
            device_projection: arkret_models_crypto::VerifiedDeviceProjection {
                device_signing_key_did: arkret_sdk::DidKey::new(
                    "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
                )
                .unwrap(),
                hpke_key: arkret_sdk::NonEmptyString::new("fixture-hpke").unwrap(),
                device_authorize_event_id: originals[0].event.event_id.clone(),
                authorized_generation_ref: 0,
                device_status: arkret_models_crypto::DeviceStatus::Active,
                authorization_window: arkret_models_crypto::DeviceAuthorizationWindow {
                    not_before: now - chrono::Duration::hours(1),
                    expires_at: None,
                },
                attested_at: now - chrono::Duration::seconds(1),
                expires_at: now + chrono::Duration::minutes(10),
            },
            authoring_generation: crate::identity::authoring_generation::AuthoringGeneration {
                authority_model:
                    crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
                authority_principal_id: account.authority.principal_id.clone(),
                generation_ref: "generation-0".into(),
            },
        }));
        let index = CurrentIndex::open(&account.authority, 0, store.current_index_location())
            .await
            .unwrap();
        let staged = stage(
            &index,
            &snapshot,
            originals
                .iter()
                .cloned()
                .map(arkret_sdk::CommittedEventView::Full)
                .collect(),
            0,
        )
        .await;
        store.commit_current_stage_for_test(staged).unwrap();
        (directory, store, account, originals[0].clone())
    }

    pub(crate) async fn install_search_disclosure(
        store: &mut crate::state::LocalStateStore,
        full: bool,
        abandon: bool,
    ) {
        let (_directory, _unused, mut snapshot, originals, _actor) = setup().await;
        let index = CurrentIndex::open(
            &store.active_authority().unwrap(),
            store.current_generation(),
            store.current_index_location(),
        )
        .await
        .unwrap();
        for row in &mut snapshot.current_state_entries {
            *row = index
                .ready_selector(
                    snapshot.realm_id.as_str(),
                    selector_of(row),
                    store.current_generation(),
                )
                .await
                .unwrap()
                .unwrap();
        }
        // Replaying a Full changes disclosure, not the already observed head.
        // Keep the latest accepted cut even when exercising an omitted crop.
        snapshot.visible_stream_heads = index
            .progress_at(snapshot.realm_id.as_str(), store.current_generation())
            .await
            .unwrap()
            .signed_snapshot
            .unwrap()
            .stream_heads;
        FixtureStation::did_web().sign_snapshot(&mut snapshot);
        let rows = if full {
            vec![arkret_sdk::CommittedEventView::Full(originals[0].clone())]
        } else {
            vec![
                serde_json::from_value(json!({
                    "commit":originals[0].commit,"event_disclosure":{"status":"withheld"}
                }))
                .unwrap(),
            ]
        };
        let staged = stage(&index, &snapshot, rows, store.current_generation()).await;
        if abandon {
            drop(staged);
        } else {
            store.commit_current_stage_for_test(staged).unwrap();
        }
    }

    pub(crate) async fn install_current_only_search_redaction(
        store: &mut crate::state::LocalStateStore,
    ) {
        install_current_only_redaction(store, false).await;
    }

    pub(crate) fn search_policy(
        original: &CommittedEventFullView,
        kind: arkret_wire::PolicyKind,
        not_before: Option<chrono::DateTime<chrono::Utc>>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> arkret_models_collaboration::governance::operation_wire::Policy {
        let policy: arkret_models_collaboration::governance::operation_wire::Policy =
            serde_json::from_value(json!({
                "id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
                "schema":"ak.schema.policy.v1", "realm_id":original.event.realm_id,
                "policy_kind":kind,"default_effect":"allow",
                "rules":[{"rule_id":"read","kind":"action","effect":"deny","actions":["ak.strand.read"]}],
                "created_by":original.event.actor_id,
                "created_at":arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now() - chrono::Duration::hours(1)),
                "not_before":not_before.map(arkret_sdk::canonical::format_timestamp_canonical),
                "expires_at":expires_at.map(arkret_sdk::canonical::format_timestamp_canonical),
            })).unwrap();
        policy.validate().unwrap();
        policy
    }

    pub(crate) async fn install_search_policies(
        store: &mut crate::state::LocalStateStore,
        policies: &[arkret_models_collaboration::governance::operation_wire::Policy],
    ) {
        assert!(!policies.is_empty());
        let (_directory, _unused, mut snapshot, originals, _actor) = setup().await;
        let original = &originals[0];
        let mut entries = vec![("ak.message.create".into(), json!(original.event.payload))];
        entries.extend(policies.iter().map(|policy| {
            policy.validate().unwrap();
            assert_eq!(policy.realm_id.as_ref(), Some(&snapshot.realm_id));
            (
                "ak.policy.set".into(),
                json!({"policy_id":policy.id,"value":policy}),
            )
        }));
        let (_, _, later) = verified_realm_fixture_as(
            "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"
                .parse()
                .unwrap(),
            entries,
            "alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        assert_eq!(later[0], *original);
        let index = CurrentIndex::open(
            &store.active_authority().unwrap(),
            store.current_generation(),
            store.current_index_location(),
        )
        .await
        .unwrap();
        let previous = &later[later.len() - 2];
        assert_eq!(
            index
                .progress_at(snapshot.realm_id.as_str(), store.current_generation())
                .await
                .unwrap()
                .signed_snapshot
                .unwrap()
                .stream_heads[0]
                .commit_id,
            previous.commit.commit_id
        );
        for row in &mut snapshot.current_state_entries {
            *row = index
                .ready_selector(
                    snapshot.realm_id.as_str(),
                    selector_of(row),
                    store.current_generation(),
                )
                .await
                .unwrap()
                .unwrap();
        }
        let full = later.last().unwrap();
        snapshot.visible_stream_heads[0].stream_position = full.commit.stream_position;
        snapshot.visible_stream_heads[0].commit_id = full.commit.commit_id.clone();
        snapshot.current_state_entries.push(TypedCurrentRow::Value {
            selector: CurrentSelector::Policy {
                policy_id: policies.last().unwrap().id.clone(),
            },
            source_stream_ref: full.commit.stream_ref.clone(),
            revision: CurrentRevision {
                commit_id: full.commit.commit_id.clone(),
                stream_position: full.commit.stream_position,
            },
            value: json!(policies.last().unwrap()),
        });
        FixtureStation::did_web().sign_snapshot(&mut snapshot);
        let staged = stage(&index, &snapshot, vec![], store.current_generation()).await;
        store.commit_current_stage_for_test(staged).unwrap();
    }

    pub(crate) async fn install_current_only_search_event_redaction(
        store: &mut crate::state::LocalStateStore,
    ) {
        install_current_only_redaction(store, true).await;
    }

    async fn install_current_only_redaction(
        store: &mut crate::state::LocalStateStore,
        event_target: bool,
    ) {
        let (_directory, _unused, mut snapshot, originals, _actor) = setup().await;
        let original = &originals[0];
        let subject = if event_target {
            original.event.event_id.to_string()
        } else {
            MessageId::from_event_id(&original.event.event_id).to_string()
        };
        let (_, _, later) = verified_realm_fixture_as(
            "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"
                .parse()
                .unwrap(),
            vec![
                (
                    "ak.message.create".into(),
                    serde_json::to_value(&original.event.payload).unwrap(),
                ),
                (
                    if event_target {
                        "ak.redaction"
                    } else {
                        "ak.message.redact"
                    }
                    .into(),
                    if event_target {
                        json!({"target_ref":subject,"preserve":["kind","actor_id","created_at"]})
                    } else {
                        json!({"message_id":subject})
                    },
                ),
            ],
            "alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        assert_eq!(later[0], *original);
        let redaction = &later[1];
        snapshot.visible_stream_heads[0].stream_position = redaction.commit.stream_position;
        snapshot.visible_stream_heads[0].commit_id = redaction.commit.commit_id.clone();
        snapshot.current_state_entries.push(TypedCurrentRow::Value {
            selector: CurrentSelector::ObjectRedaction { target_ref: subject },
            source_stream_ref: redaction.commit.stream_ref.clone(),
            revision: CurrentRevision { commit_id: redaction.commit.commit_id.clone(), stream_position: redaction.commit.stream_position },
            value: json!({"assertions":[{"tag_id":format!("{}:0",redaction.event.event_id),"value":redaction.event.payload}]}),
        });
        let index = CurrentIndex::open(
            &store.active_authority().unwrap(),
            store.current_generation(),
            store.current_index_location(),
        )
        .await
        .unwrap();
        // Preserve the installed bytes and revision of unchanged currents.
        for row in &mut snapshot.current_state_entries {
            if !matches!(selector_of(row), CurrentSelector::ObjectRedaction { .. }) {
                *row = index
                    .ready_selector(
                        snapshot.realm_id.as_str(),
                        selector_of(row),
                        store.current_generation(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
        FixtureStation::did_web().sign_snapshot(&mut snapshot);
        let staged = stage(&index, &snapshot, vec![], store.current_generation()).await;
        store.commit_current_stage_for_test(staged).unwrap();
    }

    pub(crate) async fn install_search_revision(
        store: &mut crate::state::LocalStateStore,
        include_original: bool,
    ) -> CommittedEventFullView {
        let (_directory, _unused, mut snapshot, originals, _actor) = setup().await;
        let original = &originals[0];
        let (_, _, later) = verified_realm_fixture_as(
            "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"
                .parse()
                .unwrap(),
            vec![
                ("ak.message.create".into(), json!(original.event.payload)),
                (
                    "ak.message.revise".into(),
                    json!({"message_id":MessageId::from_event_id(&original.event.event_id),"content":{"kind":"ak.content.text","format":"plain","body":"current replacement needle"}}),
                ),
            ],
            "alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        assert_eq!(later[0], *original);
        let revision = later[1].clone();
        snapshot.visible_stream_heads[0].stream_position = revision.commit.stream_position;
        snapshot.visible_stream_heads[0].commit_id = revision.commit.commit_id.clone();
        let index = CurrentIndex::open(
            &store.active_authority().unwrap(),
            store.current_generation(),
            store.current_index_location(),
        )
        .await
        .unwrap();
        for current in &mut snapshot.current_state_entries {
            if matches!(
                selector_of(current),
                CurrentSelector::MessageRevision { .. }
            ) {
                *current = TypedCurrentRow::Value {
                    selector: selector_of(current).clone(),
                    source_stream_ref: revision.commit.stream_ref.clone(),
                    revision: CurrentRevision {
                        commit_id: revision.commit.commit_id.clone(),
                        stream_position: revision.commit.stream_position,
                    },
                    value: json!(revision.event.payload),
                };
            } else {
                *current = index
                    .ready_selector(
                        snapshot.realm_id.as_str(),
                        selector_of(current),
                        store.current_generation(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
        FixtureStation::did_web().sign_snapshot(&mut snapshot);
        let rows = if include_original {
            vec![arkret_sdk::CommittedEventView::Full(revision.clone())]
        } else {
            vec![]
        };
        let staged = stage(&index, &snapshot, rows, store.current_generation()).await;
        store.commit_current_stage_for_test(staged).unwrap();
        revision
    }

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
            purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
            history_basis: None,
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
                    revision: revision.clone(),
                    value: serde_json::to_value(arkret_sdk::Strand::discussion(
                        strand,
                        bundle.realm_id.clone(),
                        "Search",
                        actor.clone(),
                    ))
                    .unwrap(),
                },
                TypedCurrentRow::Value {
                    selector: CurrentSelector::MessageRevision {
                        message_id: MessageId::from_event_id(&create.event.event_id),
                    },
                    source_stream_ref: create.commit.stream_ref.clone(),
                    revision,
                    value: json!(create.event.payload),
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
                    snapshot.current_state_entries.remove(1);
                }
                _ => {}
            }
            // Fresh signed-cut changes must use a newer row coordinate.
            for row in &mut snapshot.current_state_entries {
                if !matches!(
                    (scenario, selector_of(row)),
                    ("leave", CurrentSelector::MemberState { .. })
                        | ("wrong_scope", CurrentSelector::Strand { .. })
                ) {
                    continue;
                }
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
            if row.event.kind == EventKind::MessageRevise {
                snapshot.current_state_entries[2] = TypedCurrentRow::Value {
                    selector: CurrentSelector::MessageRevision {
                        message_id: message.clone(),
                    },
                    source_stream_ref: row.commit.stream_ref.clone(),
                    revision: CurrentRevision {
                        commit_id: row.commit.commit_id.clone(),
                        stream_position: row.commit.stream_position,
                    },
                    value: json!(row.event.payload),
                };
            }
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
