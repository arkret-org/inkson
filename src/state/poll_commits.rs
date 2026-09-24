//! Durable MessageCreate coordinates from a cryptographically verified scan.
//!
//! The ordinary Realm scanner currently uses Garth's shape-only `apply_scan`.
//! Its `ClientEvent::Committed` values are not admitted here. Once that scanner
//! installs a fresh authority bundle and calls `apply_verified_scan`, its
//! unforgeable `VerifiedScanPage` can feed this index. Poll plaintext still
//! needs an exact per-partition reducer before a stored coordinate can author
//! a replacement declaration.

use super::*;

const VERIFIED_MESSAGE_COMMITS_MAX: usize = 512;

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
    /// Stage verified coordinates in the existing account-state blob. On wasm,
    /// the caller must await `begin_durable_flush()` before ACKing the scan
    /// cursor: `flush()` alone only enqueues the IndexedDB write.
    pub(crate) fn ingest_verified_message_commits(
        &mut self,
        page: &garth::VerifiedScanPage,
    ) -> Result<usize, String> {
        let mut pending = Vec::new();
        for view in page.rows() {
            let arkret_sdk::CommittedEventView::Full(full) = view else {
                continue;
            };
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
        self.persist_verified_message_commits(pending)
    }

    fn persist_verified_message_commits(
        &mut self,
        pending: Vec<VerifiedMessageCommit>,
    ) -> Result<usize, String> {
        if self.flush_suspended > 0 {
            return Err(
                "verified message Commit index cannot persist inside a state batch".to_owned(),
            );
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
