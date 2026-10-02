//! Durable MessageCreate coordinates from a cryptographically verified scan.
//!
//! Only Garth's unforgeable `VerifiedScanPage` supplies original poll inputs.
//! The bounded message-coordinate cache is independent from the poll archive:
//! response history is retained so replay can rebuild the SDK partition reducer.

use super::*;

const VERIFIED_MESSAGE_COMMITS_MAX: usize = 512;
const VERIFIED_REACTION_WINNERS_MAX: usize = 512;

fn reaction_key(
    record: &VerifiedReactionAssertion,
) -> Result<(arkret_sdk::ActorId, arkret_sdk::ScopeRef, String, String), String> {
    let payload: arkret_sdk::ReactionPayload = serde_json::to_value(&record.event.payload)
        .and_then(serde_json::from_value)
        .map_err(|error| format!("verified reaction payload is invalid: {error}"))?;
    arkret_sdk::MessageId::new(payload.target_ref.clone())
        .map_err(|error| format!("verified reaction target is not a Message: {error}"))?;
    if payload.key.is_empty() {
        return Err("verified reaction key is empty".to_owned());
    }
    Ok((
        record.event.actor_id.clone(),
        record.event.scope_ref.clone(),
        payload.target_ref.to_string(),
        payload.key,
    ))
}

fn merge_verified_reaction_assertions(
    next: &mut Vec<VerifiedReactionAssertion>,
    pending: Vec<VerifiedReactionAssertion>,
) -> Result<(), String> {
    for record in pending {
        if let Some(previous) = next
            .iter()
            .find(|previous| previous.accepted_ref.event_id == record.accepted_ref.event_id)
        {
            if previous != &record {
                return Err("conflicting verified reaction Event identity".to_owned());
            }
            continue;
        }
        if let Some(previous) = next.iter().find(|previous| {
            previous.accepted_ref.stream_ref == record.accepted_ref.stream_ref
                && previous.accepted_ref.stream_position == record.accepted_ref.stream_position
        }) {
            if previous != &record {
                return Err("conflicting verified reaction Commit position".to_owned());
            }
            continue;
        }
        let key = reaction_key(&record)?;
        if let Some(index) = next
            .iter()
            .position(|previous| reaction_key(previous).ok().as_ref() == Some(&key))
        {
            if next[index].accepted_ref.stream_ref != record.accepted_ref.stream_ref {
                return Err("reaction key crosses authority streams".to_owned());
            }
            if record.accepted_ref.stream_position > next[index].accepted_ref.stream_position {
                next[index] = record;
            }
        } else {
            if next.len() >= VERIFIED_REACTION_WINNERS_MAX {
                return Err("verified reaction winner inventory is full".to_owned());
            }
            next.push(record);
        }
    }
    Ok(())
}

fn merge_verified_message_commits(
    next: &mut Vec<VerifiedMessageCommit>,
    pending: Vec<VerifiedMessageCommit>,
) -> Result<usize, String> {
    let mut changed = 0;
    for record in pending {
        if let Some(previous) = next
            .iter()
            .find(|entry| entry.accepted_ref.event_id == record.accepted_ref.event_id)
        {
            if previous != &record {
                return Err("conflicting verified MessageCreate coordinate".to_owned());
            }
            continue;
        }
        next.push(record);
        changed += 1;
    }
    // An evicted coordinate becomes unknown, never a negative or a head.
    // A later verified replay may reinsert it; conflict detection covers only
    // the retained window. The scan verifier still checks every replayed row.
    if next.len() > VERIFIED_MESSAGE_COMMITS_MAX {
        next.drain(0..next.len() - VERIFIED_MESSAGE_COMMITS_MAX);
    }
    Ok(changed)
}

impl LocalStateStore {
    /// Retain a cryptographically verified shared page before any private
    /// timeline filtering. The caller owns the stream checkpoint transaction.
    pub fn ingest_verified_message_history(
        &mut self,
        page: &garth::VerifiedScanPage,
    ) -> Result<usize, String> {
        let verified_changes = self.ingest_verified_message_commits(page)?;
        let events = page
            .rows()
            .iter()
            .filter_map(|view| {
                if let arkret_sdk::CommittedEventView::Full(full) = view {
                    Some(garth::ClientEvent::Event(Box::new(full.event.clone())))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(verified_changes + crate::sync_engine::ingest_message_events(self, "", &events))
    }

    pub(crate) fn verified_commit_stream_cursor(
        &self,
        stream_ref: &arkret_sdk::CommitStreamRef,
    ) -> Result<Option<arkret_sdk::CommitStreamHead>, String> {
        let key = serde_json::to_string(stream_ref).map_err(|error| error.to_string())?;
        Ok(self
            .load()
            .verified_commit_stream_cursors
            .get(&key)
            .cloned())
    }

    pub(crate) fn save_verified_commit_stream_cursor(
        &mut self,
        stream_ref: &arkret_sdk::CommitStreamRef,
        head: arkret_sdk::CommitStreamHead,
    ) -> Result<(), String> {
        let key = serde_json::to_string(stream_ref).map_err(|error| error.to_string())?;
        self.ensure_cached_loaded();
        if &head.stream_ref != stream_ref {
            return Err("verified stream cursor belongs to another stream".to_owned());
        }
        let previous = self
            .cached
            .verified_commit_stream_cursors
            .insert(key.clone(), head);
        if let Err(error) = self.flush() {
            match previous {
                Some(previous) => {
                    self.cached
                        .verified_commit_stream_cursors
                        .insert(key, previous);
                }
                None => {
                    self.cached.verified_commit_stream_cursors.remove(&key);
                }
            }
            return Err(format!("persist verified commit stream cursor: {error}"));
        }
        Ok(())
    }

    /// Stage verified coordinates in the existing account-state blob. On wasm,
    /// the caller must await `begin_durable_flush()` before ACKing the scan
    /// cursor: `flush()` alone only enqueues the IndexedDB write.
    pub(crate) fn ingest_verified_message_commits(
        &mut self,
        page: &garth::VerifiedScanPage,
    ) -> Result<usize, String> {
        let mut pending = Vec::new();
        let mut pending_reactions = Vec::new();
        let mut genesis_roles = BTreeMap::new();
        for view in page.rows() {
            let arkret_sdk::CommittedEventView::Full(full) = view else {
                continue;
            };
            if full.event.kind == arkret_sdk::EventKind::RealmCreate
                && let Ok(payload) = serde_json::to_value(&full.event.payload)
                    .and_then(serde_json::from_value::<arkret_sdk::RealmCreatePayload>)
            {
                let realm = arkret_sdk::RealmId::from_event_id(&full.event.event_id);
                if full.commit.stream_position != 0
                    || full.event.realm_id != realm
                    || full.commit.realm_id != realm
                    || full.commit.event_ref != full.event.event_id
                    || full.commit.previous_commit_ref.is_some()
                    || full.commit.stream_ref
                        != (arkret_sdk::CommitStreamRef::Realm {
                            realm_id: realm.clone(),
                        })
                    || full.event.scope_ref != arkret_sdk::ScopeRef::RealmGenesis
                {
                    return Err("verified Realm genesis has inconsistent coordinates".to_owned());
                }
                payload
                    .object
                    .validate()
                    .map_err(|error| error.to_string())?;
                let role = (payload.object.purpose == arkret_sdk::RealmPurpose::DirectConversation)
                    .then_some(arkret_sdk::CollaborationRealmRole::DirectConversation);
                genesis_roles.insert(realm.to_string(), role);
            }
            if matches!(
                full.event.kind,
                arkret_sdk::EventKind::ReactionAdd | arkret_sdk::EventKind::ReactionRemove
            ) {
                let commit = &full.commit;
                let event = &full.event;
                let expected_stream = arkret_sdk::CommitStreamRef::from_scope(
                    &event.scope_ref,
                    Some(event.realm_id.clone()),
                )
                .map_err(|error| format!("reaction scope has no authority stream: {error}"))?;
                if commit.event_ref != event.event_id
                    || commit.realm_id != event.realm_id
                    || commit.stream_ref != expected_stream
                {
                    return Err("verified reaction Commit and Event coordinates differ".to_owned());
                }
                pending_reactions.push(VerifiedReactionAssertion {
                    accepted_ref: arkret_sdk::CommittedEventRef {
                        event_id: event.event_id.clone(),
                        commit_id: commit.commit_id.clone(),
                        stream_ref: commit.stream_ref.clone(),
                        stream_position: commit.stream_position,
                    },
                    event: event.clone(),
                });
            }
            if full.event.kind != arkret_sdk::EventKind::MessageCreate {
                continue;
            }
            let commit = &full.commit;
            let event = &full.event;
            if commit.event_ref != event.event_id
                || commit.realm_id != event.realm_id
                || !matches!(
                    (&commit.stream_ref, &event.scope_ref),
                    (
                        arkret_sdk::CommitStreamRef::Realm { realm_id: committed },
                        arkret_sdk::ScopeRef::Realm { realm_id: signed },
                    ) if committed == signed
                ) && !matches!(
                    (&commit.stream_ref, &event.scope_ref),
                    (
                        arkret_sdk::CommitStreamRef::Circle { realm_id: committed_realm, circle_id: committed_circle },
                        arkret_sdk::ScopeRef::Circle { realm_id: signed_realm, circle_id: signed_circle },
                    ) if committed_realm == signed_realm && committed_circle == signed_circle
                )
            {
                return Err("verified message Commit and Event coordinates differ".to_owned());
            }
            pending.push(VerifiedMessageCommit {
                accepted_ref: arkret_sdk::CommittedEventRef {
                    event_id: event.event_id.clone(),
                    commit_id: commit.commit_id.clone(),
                    stream_ref: commit.stream_ref.clone(),
                    stream_position: commit.stream_position,
                },
                actor_id: event.actor_id.clone(),
                scope_ref: event.scope_ref.clone(),
            });
        }
        self.ensure_cached_loaded();
        let prior_inputs = self.cached.verified_poll_inputs.clone();
        let prior_prefixes = self.cached.verified_poll_prefixes.clone();
        let prior_reactions = self.cached.verified_reaction_assertions.clone();
        let prior_roles = self.cached.realm_collaboration_roles.clone();
        merge_verified_poll_page(
            &mut self.cached.verified_poll_inputs,
            &mut self.cached.verified_poll_prefixes,
            page.rows(),
        )?;
        if let Err(error) = merge_verified_reaction_assertions(
            &mut self.cached.verified_reaction_assertions,
            pending_reactions,
        ) {
            self.cached.verified_poll_inputs = prior_inputs;
            self.cached.verified_poll_prefixes = prior_prefixes;
            self.cached.verified_reaction_assertions = prior_reactions;
            return Err(error);
        }
        for (realm, role) in genesis_roles {
            match role {
                Some(role) => {
                    self.cached.realm_collaboration_roles.insert(realm, role);
                }
                None => {
                    self.cached.realm_collaboration_roles.remove(&realm);
                }
            }
        }
        match self.persist_verified_message_commits(pending) {
            Ok(changed) => Ok(changed
                + usize::from(self.cached.verified_poll_inputs != prior_inputs)
                + usize::from(self.cached.verified_poll_prefixes != prior_prefixes)
                + usize::from(self.cached.verified_reaction_assertions != prior_reactions)
                + usize::from(self.cached.realm_collaboration_roles != prior_roles)),
            Err(error) => {
                self.cached.verified_poll_inputs = prior_inputs;
                self.cached.verified_poll_prefixes = prior_prefixes;
                self.cached.verified_reaction_assertions = prior_reactions;
                self.cached.realm_collaboration_roles = prior_roles;
                Err(error)
            }
        }
    }

    fn persist_verified_message_commits(
        &mut self,
        pending: Vec<VerifiedMessageCommit>,
    ) -> Result<usize, String> {
        self.ensure_cached_loaded();
        let mut next = self.cached.verified_message_commits.clone();
        let changed = merge_verified_message_commits(&mut next, pending)?;
        if changed == 0 {
            // A wasm queue can report a later IndexedDB failure after the
            // in-memory index changed. Re-enqueue exact replay so a caller
            // can retry its durable barrier before moving the scan cursor.
            self.flush()
                .map_err(|error| format!("persist verified message Commits: {error}"))?;
            return Ok(0);
        }
        let previous = std::mem::replace(&mut self.cached.verified_message_commits, next);
        if let Err(error) = self.flush() {
            self.cached.verified_message_commits = previous;
            return Err(format!("persist verified message Commits: {error}"));
        }
        Ok(changed)
    }

    pub(crate) fn verified_message_commit(
        &self,
        event_id: &arkret_sdk::EventId,
    ) -> Option<VerifiedMessageCommit> {
        self.load()
            .verified_message_commits
            .into_iter()
            .find(|entry| &entry.accepted_ref.event_id == event_id)
    }

    pub(crate) fn verified_poll_inputs(&self) -> Vec<VerifiedPollInput> {
        self.load().verified_poll_inputs
    }

    pub(crate) fn verified_poll_partition_complete(
        &self,
        stream: &arkret_sdk::CommitStreamRef,
        poll_position: u64,
    ) -> bool {
        serde_json::to_string(stream)
            .ok()
            .and_then(|key| self.load().verified_poll_prefixes.get(&key).cloned())
            .is_some_and(|prefix| {
                prefix.contiguous
                    && prefix.start_position <= poll_position
                    && poll_position <= prefix.head.stream_position
            })
    }
}

// Private to the verified carrier adapter above. Tests exercise durable replay
// and conflict handling without constructing a public trust-token shortcut.
fn merge_verified_poll_page(
    inputs: &mut Vec<VerifiedPollInput>,
    prefixes: &mut BTreeMap<String, VerifiedPollPrefix>,
    rows: &[arkret_sdk::CommittedEventView],
) -> Result<(), String> {
    let mut next_inputs = inputs.clone();
    let mut next_prefixes = prefixes.clone();
    for view in rows {
        let commit = view.commit();
        if matches!(
            commit.stream_ref,
            arkret_sdk::CommitStreamRef::Sidecar { .. }
        ) {
            continue;
        }
        let key = serde_json::to_string(&commit.stream_ref).map_err(|error| error.to_string())?;
        let full = matches!(view, arkret_sdk::CommittedEventView::Full(_));
        if !full {
            next_inputs.retain(|input| input.accepted_ref.event_id != commit.event_ref);
        }
        let previous = next_prefixes.get(&key);
        let extends = previous.is_some_and(|prefix| {
            prefix.contiguous
                && prefix.head.stream_position.checked_add(1) == Some(commit.stream_position)
                && commit.previous_commit_ref.as_ref() == Some(&prefix.head.commit_id)
        });
        let start_position = if extends && full {
            previous.expect("extended range").start_position
        } else {
            commit.stream_position
        };
        // A verified re-scan starts at genesis and rebuilds continuity. Late
        // individual rows do not turn a newer verified prefix into a gap.
        if (commit.stream_position == 0
            && !previous.is_some_and(|prefix| {
                prefix.contiguous && prefix.start_position == 0 && prefix.head.stream_position > 0
            }))
            || previous.is_none_or(|prefix| commit.stream_position > prefix.head.stream_position)
        {
            next_prefixes.insert(
                key,
                VerifiedPollPrefix {
                    head: arkret_sdk::CommitStreamHead {
                        stream_ref: commit.stream_ref.clone(),
                        commit_id: commit.commit_id.clone(),
                        stream_position: commit.stream_position,
                    },
                    start_position,
                    contiguous: full,
                },
            );
        } else if !full && let Some(prefix) = next_prefixes.get_mut(&key) {
            prefix.contiguous = false;
        }
        let arkret_sdk::CommittedEventView::Full(full) = view else {
            continue;
        };
        let event = &full.event;
        if event.kind != arkret_sdk::EventKind::MessageCreate {
            continue;
        }
        let is_poll = event
            .payload
            .get("content")
            .and_then(|content| content.get("kind"))
            .and_then(Value::as_str)
            .is_some_and(|kind| matches!(kind, "ak.content.poll" | "ak.content.poll.response"));
        if !is_poll {
            continue;
        }
        let record = VerifiedPollInput {
            accepted_ref: arkret_sdk::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            },
            event: event.clone(),
        };
        if let Some(previous) = next_inputs
            .iter()
            .find(|entry| entry.accepted_ref.event_id == record.accepted_ref.event_id)
        {
            if previous != &record {
                return Err("conflicting verified poll input".to_owned());
            }
        } else {
            if next_inputs.iter().any(|entry| {
                entry.accepted_ref.stream_ref == record.accepted_ref.stream_ref
                    && entry.accepted_ref.stream_position == record.accepted_ref.stream_position
            }) {
                return Err("conflicting verified poll Commit position".to_owned());
            }
            next_inputs.push(record);
        }
    }
    *inputs = next_inputs;
    *prefixes = next_prefixes;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_genesis_scope_persists_only_the_signed_direct_role() {
        use crate::test_support::committed_event::{FixtureStation, fixture_time};
        for purpose in [
            arkret_sdk::RealmPurpose::DirectConversation,
            arkret_sdk::RealmPurpose::Collaboration,
        ] {
            let station = FixtureStation::did_web();
            let genesis = arkret_sdk::RealmGenesis::new(
                purpose,
                arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
                arkret_sdk::SecurityClass::Standard,
                station.service_id().clone(),
                arkret_sdk::JoinRule::Invite,
                arkret_sdk::HistoryAccess::SinceJoin,
                arkret_sdk::Discoverability::Listed,
                None,
                None,
            )
            .unwrap();
            let signer = arkret_test_kit::keys::seeded_signer(
                arkret_sdk::Did::new("did:web:alice.example").unwrap(),
                arkret_sdk::DidUrl::new("did:web:alice.example#device").unwrap(),
            );
            let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                station.service_id().clone(),
            ));
            let event = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
                arkret_sdk::EventKind::RealmCreate.as_str(),
                arkret_sdk::ScopeRef::RealmGenesis,
                actor,
                serde_json::json!({"object": genesis}),
            )
            .with_created_at(fixture_time(0))
            .sign_verifiable(&signer)
            .unwrap()
            .expect_verifiable();
            let realm = event.realm_id.clone();
            let stream = arkret_sdk::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            };
            let (mut bundle, keys, _) =
                crate::test_support::committed_event::verified_realm_fixture_signed_by(
                    &station,
                    realm.clone(),
                    serde_json::json!({}),
                    Vec::new(),
                    "alice.example",
                    "ak:device:0196419b-0000-7000-8000-000000000001",
                );
            bundle.genesis_event = event.clone();
            bundle.genesis_commit.event_ref = event.event_id.clone();
            bundle.genesis_commit.authority_ref =
                arkret_sdk::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
            bundle.genesis_commit = station.seal_commit(bundle.genesis_commit);
            bundle.realm_stream_head.commit_id = bundle.genesis_commit.commit_id.clone();
            bundle.current_assertion.realm_stream_head = bundle.realm_stream_head.clone();
            let nonce = bundle.current_assertion.nonce.clone();
            station.reassert_for_nonce(&mut bundle, nonce.clone(), fixture_time(50));
            let request = arkret_sdk::AuthorityBundleRequest {
                realm_id: realm.clone(),
                nonce: nonce.clone(),
            };
            let freshness = arkret_identity::RealmAuthorityFreshness::new(fixture_time(100), nonce);
            let mut replica = garth::RealmReplica::new(realm.clone());
            replica
                .install_verified_authority(&request, bundle.clone(), &freshness, &keys)
                .unwrap();
            let scan = arkret_sdk::StreamScanRequest {
                realm_id: realm.clone(),
                stream_ref: stream,
                direction: arkret_sdk::StreamScanDirection::After(None),
                limit: 1,
            };
            let page = replica
                .apply_verified_scan(
                    &scan,
                    arkret_sdk::StreamScanOutcome {
                        committed_events: vec![arkret_sdk::CommittedEventView::Full(
                            arkret_sdk::CommittedEventFullView {
                                commit: bundle.genesis_commit.clone(),
                                event,
                            },
                        )],
                        readable_floor: Some(arkret_sdk::ReadableFloor {
                            oldest_position: 0,
                            floor_commit_id: bundle.genesis_commit.commit_id,
                            floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
                        }),
                        truncated: false,
                    },
                    &freshness,
                    &keys,
                )
                .unwrap();
            let path = std::env::temp_dir().join(format!(
                "inkson-genesis-{}.json",
                crate::operation::uuid_v7()
            ));
            let mut store = LocalStateStore::with_path(&path);
            store.ingest_verified_message_history(&page).unwrap();
            let expected = (purpose == arkret_sdk::RealmPurpose::DirectConversation)
                .then_some(arkret_sdk::CollaborationRealmRole::DirectConversation);
            assert_eq!(
                LocalStateStore::with_path(&path)
                    .load()
                    .realm_collaboration_roles
                    .get(realm.as_str())
                    .cloned(),
                expected
            );
            assert_eq!(store.ingest_verified_message_history(&page).unwrap(), 0);
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn signed_reaction_commits_survive_reopen_and_older_replay_cannot_restore_removed_member() {
        let realm =
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        let create_payload = serde_json::json!({
            "strand_id": "ak:strand:AbZt0K_NvenxSDAkOnSDRtorrvUXhGqxSoqT2bFL7m8H",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "reaction target"}
        });
        let first = crate::test_support::committed_event::verified_realm_item_as(
            realm.clone(),
            arkret_sdk::EventKind::MessageCreate.as_str(),
            create_payload.clone(),
            "bob.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        let target = arkret_sdk::MessageId::from_event_id(&first.event.event_id);
        let (bundle, keys, items) = crate::test_support::committed_event::verified_realm_fixture_as(
            realm.clone(),
            vec![
                (
                    arkret_sdk::EventKind::MessageCreate.as_str().to_owned(),
                    create_payload,
                ),
                (
                    arkret_sdk::EventKind::ReactionAdd.as_str().to_owned(),
                    serde_json::json!({"target_ref": target, "key": "👍"}),
                ),
                (
                    arkret_sdk::EventKind::ReactionRemove.as_str().to_owned(),
                    serde_json::json!({"target_ref": target, "key": "👍"}),
                ),
            ],
            "bob.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        assert_eq!(items[0].event.event_id, first.event.event_id);
        let stream_ref = arkret_sdk::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let request = arkret_sdk::AuthorityBundleRequest {
            realm_id: realm.clone(),
            nonce: bundle.current_assertion.nonce.clone(),
        };
        let freshness = arkret_identity::RealmAuthorityFreshness::new(
            bundle.bundle_issued_at + chrono::Duration::seconds(50),
            request.nonce.clone(),
        );
        let mut replica = garth::RealmReplica::new(realm.clone());
        replica
            .install_verified_authority(&request, bundle.clone(), &freshness, &keys)
            .unwrap();
        let first_scan = arkret_sdk::StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream_ref.clone(),
            direction: arkret_sdk::StreamScanDirection::After(None),
            limit: 3,
        };
        let first_outcome = arkret_sdk::StreamScanOutcome {
            committed_events: std::iter::once(arkret_sdk::CommittedEventView::Full(
                arkret_sdk::CommittedEventFullView {
                    commit: bundle.genesis_commit.clone(),
                    event: bundle.genesis_event.clone(),
                },
            ))
            .chain(
                items[..2]
                    .iter()
                    .cloned()
                    .map(arkret_sdk::CommittedEventView::Full),
            )
            .collect(),
            readable_floor: Some(arkret_sdk::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: bundle.genesis_commit.commit_id.clone(),
                floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
            }),
            truncated: true,
        };
        let first_page = replica
            .apply_verified_scan(&first_scan, first_outcome, &freshness, &keys)
            .unwrap();
        let later_scan = arkret_sdk::StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream_ref.clone(),
            direction: arkret_sdk::StreamScanDirection::After(Some(2)),
            limit: 1,
        };
        let later_page = replica
            .apply_verified_scan(
                &later_scan,
                arkret_sdk::StreamScanOutcome {
                    committed_events: vec![arkret_sdk::CommittedEventView::Full(items[2].clone())],
                    readable_floor: Some(arkret_sdk::ReadableFloor {
                        oldest_position: 0,
                        floor_commit_id: bundle.genesis_commit.commit_id.clone(),
                        floor_reason: arkret_sdk::ReadableFloorReason::StreamStart,
                    }),
                    truncated: false,
                },
                &freshness,
                &keys,
            )
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "inkson-reaction-verified-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = LocalStateStore::with_path(&path);
        store
            .verified_projection_transaction(|store| {
                store.ingest_verified_message_history(&first_page)?;
                store.save_verified_commit_stream_cursor(
                    &stream_ref,
                    arkret_sdk::CommitStreamHead {
                        stream_ref: stream_ref.clone(),
                        stream_position: items[1].commit.stream_position,
                        commit_id: items[1].commit.commit_id.clone(),
                    },
                )
            })
            .unwrap();
        let first_state = LocalStateStore::with_path(&path).load();
        let first_messages = crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
            &first_state,
            None,
            None,
        );
        assert_eq!(first_messages.len(), 1);
        assert_eq!(first_messages[0].reactions.len(), 1);
        assert_eq!(
            first_messages[0].reactions[0].1,
            vec![items[1].event.actor_id.to_string()]
        );
        let mut since_join = first_state.clone();
        let target_position = since_join.verified_message_commits[0]
            .accepted_ref
            .stream_position;
        assert!(target_position > 0);
        for prefix in since_join.verified_poll_prefixes.values_mut() {
            prefix.start_position = target_position;
        }
        assert_eq!(
            crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
                &since_join,
                None,
                None,
            )[0]
            .reactions,
            first_messages[0].reactions,
            "a complete target-to-reaction chain does not require pre-join genesis history"
        );
        for prefix in since_join.verified_poll_prefixes.values_mut() {
            prefix.start_position = target_position + 1;
        }
        assert!(
            crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
                &since_join,
                None,
                None,
            )[0]
            .reactions
            .is_empty(),
            "a retained target coordinate cannot fill a gap before the reaction"
        );
        let mut no_target_coordinate = first_state.clone();
        no_target_coordinate.verified_message_commits.clear();
        assert!(
            crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
                &no_target_coordinate,
                None,
                None,
            )[0]
            .reactions
            .is_empty(),
            "a signed reaction cannot prove its target scope without a verified MessageCreate"
        );
        let mut mismatched_target_scope = first_state.clone();
        mismatched_target_scope.verified_message_commits[0].scope_ref =
            arkret_sdk::ScopeRef::RealmGenesis;
        assert!(
            crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
                &mismatched_target_scope,
                None,
                None,
            )[0]
            .reactions
            .is_empty(),
            "a reaction must not cross the target Message's effective scope"
        );
        let mut shape_only = first_state.clone();
        shape_only.verified_reaction_assertions.clear();
        assert!(
            crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
                &shape_only,
                None,
                None,
            )[0]
            .reactions
            .is_empty(),
            "signed bare Events without a verified Commit must not assert membership"
        );
        let mut joined_suffix = first_state.clone();
        let target_position = joined_suffix.verified_message_commits[0]
            .accepted_ref
            .stream_position;
        assert!(target_position > 0);
        for prefix in joined_suffix.verified_poll_prefixes.values_mut() {
            prefix.start_position = target_position;
        }
        assert_eq!(
            crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
                &joined_suffix,
                None,
                None,
            )[0]
            .reactions,
            first_messages[0].reactions,
            "a contiguous authorized suffix covering the target includes all possible reactions"
        );
        for prefix in joined_suffix.verified_poll_prefixes.values_mut() {
            prefix.start_position = target_position + 1;
        }
        assert!(
            crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
                &joined_suffix,
                None,
                None,
            )[0]
            .reactions
            .is_empty(),
            "a suffix starting after the target cannot establish complete reaction membership"
        );
        let mut incomplete = first_state;
        for prefix in incomplete.verified_poll_prefixes.values_mut() {
            prefix.contiguous = false;
        }
        assert!(
            crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
                &incomplete,
                None,
                None,
            )[0]
            .reactions
            .is_empty(),
            "a missing stream prefix cannot be called converged"
        );
        let mut continuation = LocalStateStore::with_path(&path);
        continuation
            .verified_projection_transaction(|store| {
                assert!(
                    store.ingest_verified_message_history(&later_page)? > 0,
                    "a reaction-only page must invalidate the live timeline"
                );
                store.save_verified_commit_stream_cursor(
                    &stream_ref,
                    arkret_sdk::CommitStreamHead {
                        stream_ref: stream_ref.clone(),
                        stream_position: items[2].commit.stream_position,
                        commit_id: items[2].commit.commit_id.clone(),
                    },
                )
            })
            .unwrap();
        let mut persisted = LocalStateStore::with_path(&path).load();
        assert_eq!(persisted.verified_reaction_assertions.len(), 1);
        assert_eq!(
            persisted.verified_reaction_assertions[0]
                .accepted_ref
                .stream_position,
            items[2].commit.stream_position
        );
        assert_eq!(
            persisted.verified_reaction_assertions[0].event.kind,
            arkret_sdk::EventKind::ReactionRemove
        );
        let messages = crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
            &persisted, None, None,
        );
        assert_eq!(messages.len(), 1);
        assert!(messages[0].reactions.is_empty());
        persisted.raw_operations.reverse();
        let reversed = crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
            &persisted, None, None,
        );
        assert_eq!(reversed.len(), 1);
        assert!(reversed[0].reactions.is_empty());
        let mut replay = LocalStateStore::with_path(&path);
        replay.ingest_verified_message_history(&first_page).unwrap();
        assert_eq!(replay.load().verified_reaction_assertions.len(), 1);
        assert_eq!(
            replay.load().verified_reaction_assertions[0].event.kind,
            arkret_sdk::EventKind::ReactionRemove
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verified_cursor_transaction_rolls_back_and_never_uses_shape_cursor() {
        let path = std::env::temp_dir().join(format!(
            "inkson-verified-cursor-{}.json",
            crate::operation::uuid_v7()
        ));
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        let stream_ref = arkret_sdk::CommitStreamRef::Realm { realm_id };
        let head = arkret_sdk::CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: 2,
            commit_id: arkret_sdk::RealmCommitId::from_digest([0x62; 32]),
        };
        let mut store = LocalStateStore::with_path(&path);
        let failed: Result<(), String> = store.verified_projection_transaction(|store| {
            store.save_verified_commit_stream_cursor(&stream_ref, head.clone())?;
            Err("bad second page".to_owned())
        });
        assert_eq!(failed.unwrap_err(), "bad second page");
        assert_eq!(
            store.verified_commit_stream_cursor(&stream_ref).unwrap(),
            None
        );
        assert_eq!(
            LocalStateStore::with_path(&path)
                .verified_commit_stream_cursor(&stream_ref)
                .unwrap(),
            None
        );
        store
            .verified_projection_transaction(|store| {
                store.save_verified_commit_stream_cursor(&stream_ref, head.clone())
            })
            .unwrap();
        assert_eq!(
            LocalStateStore::with_path(&path)
                .verified_commit_stream_cursor(&stream_ref)
                .unwrap(),
            Some(head)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verified_message_coordinates_replay_and_conflicts_fail_closed() {
        let realm =
            arkret_sdk::RealmId::new("ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q")
                .unwrap();
        let event_id =
            arkret_sdk::EventId::new("ak:event:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu")
                .unwrap();
        let record = VerifiedMessageCommit {
            accepted_ref: arkret_sdk::CommittedEventRef {
                event_id,
                commit_id: arkret_sdk::RealmCommitId::from_digest([0x41; 32]),
                stream_ref: arkret_sdk::CommitStreamRef::Realm {
                    realm_id: realm.clone(),
                },
                stream_position: 7,
            },
            actor_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            scope_ref: arkret_sdk::ScopeRef::Realm { realm_id: realm },
        };
        let mut stored = Vec::new();
        assert_eq!(
            merge_verified_message_commits(&mut stored, vec![record.clone()]).unwrap(),
            1
        );
        assert_eq!(
            merge_verified_message_commits(&mut stored, vec![record.clone()]).unwrap(),
            0
        );
        let mut conflict = record;
        conflict.accepted_ref.stream_position = 8;
        assert!(merge_verified_message_commits(&mut stored, vec![conflict]).is_err());
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].accepted_ref.stream_position, 7);

        let path = std::env::temp_dir().join(format!(
            "inkson-verified-message-commits-{}",
            crate::operation::uuid_v7()
        ));
        let mut store = LocalStateStore::with_path(path.clone());
        assert_eq!(
            store
                .persist_verified_message_commits(vec![stored[0].clone()])
                .unwrap(),
            1
        );
        drop(store);
        let mut restarted = LocalStateStore::with_path(path);
        assert_eq!(
            restarted
                .verified_message_commit(&stored[0].accepted_ref.event_id)
                .as_ref(),
            Some(&stored[0])
        );
        assert_eq!(
            restarted
                .persist_verified_message_commits(vec![stored[0].clone()])
                .unwrap(),
            0
        );
        let mut conflicting = stored[0].clone();
        conflicting.accepted_ref.stream_position = 8;
        assert!(
            restarted
                .persist_verified_message_commits(vec![conflicting])
                .is_err()
        );
        assert_eq!(
            restarted
                .verified_message_commit(&stored[0].accepted_ref.event_id)
                .as_ref(),
            Some(&stored[0])
        );

        let blocked_parent = std::env::temp_dir().join(format!(
            "inkson-verified-message-blocked-{}",
            crate::operation::uuid_v7()
        ));
        std::fs::write(&blocked_parent, b"not a directory").unwrap();
        let blocked_path = blocked_parent.join("state.json");
        let mut blocked = LocalStateStore::with_path(blocked_path.clone());
        assert!(
            blocked
                .persist_verified_message_commits(vec![stored[0].clone()])
                .is_err()
        );
        assert!(
            blocked
                .verified_message_commit(&stored[0].accepted_ref.event_id)
                .is_none(),
            "failed flush must restore the previous in-memory index"
        );
        std::fs::remove_file(&blocked_parent).unwrap();
        std::fs::create_dir(&blocked_parent).unwrap();
        assert_eq!(
            blocked
                .persist_verified_message_commits(vec![stored[0].clone()])
                .unwrap(),
            1,
            "retry after storage recovery must perform the write"
        );
        drop(blocked);
        let reopened = LocalStateStore::with_path(blocked_path);
        assert_eq!(
            reopened
                .verified_message_commit(&stored[0].accepted_ref.event_id)
                .as_ref(),
            Some(&stored[0])
        );
    }
}
