//! Private replay material, admitted only by the shared signature verifiers.

use std::collections::BTreeMap;

use arkret_sdk::{CommitStreamRef, CommittedEventView, RealmStateSnapshot};

use super::LocalStateStore;

impl LocalStateStore {
    /// Restore a hosted route only from the complete signed private current
    /// cut and its exact accepted context attachment. A local locator or a
    /// shape-only directory response cannot activate another Strand.
    pub(crate) fn verified_sidecar_for_source(
        &self,
        controller: &arkret_sdk::AccountId,
        realm: &str,
        strand: &arkret_sdk::StrandId,
    ) -> anyhow::Result<Option<arkret_sdk::AgentSidecar>> {
        use arkret_sdk::{CurrentSelector, EventKind, SidecarContextRef, TypedCurrentRow};
        let (snapshot, histories) = self.verified_sidecar_inputs(realm)?;
        let source = SidecarContextRef::Strand {
            strand_id: strand.clone(),
        };
        let mut found = None;
        for row in &snapshot.current_state_entries {
            let TypedCurrentRow::Value {
                selector:
                    CurrentSelector::SidecarContext {
                        sidecar_id,
                        source_context_ref,
                    },
                source_stream_ref,
                revision,
                value,
            } = row
            else {
                continue;
            };
            if source_context_ref != &source {
                continue;
            }
            let stream = CommitStreamRef::Sidecar {
                realm_id: snapshot.realm_id.clone(),
                sidecar_id: sidecar_id.clone(),
            };
            anyhow::ensure!(
                source_stream_ref == &stream,
                "Sidecar context current crosses its native stream"
            );
            let history = histories
                .get(sidecar_id.as_str())
                .ok_or_else(|| anyhow::anyhow!("Sidecar source context has no verified history"))?;
            let attached = history
                .iter()
                .find(|full| {
                    full.commit.commit_id == revision.commit_id
                        && full.commit.stream_position == revision.stream_position
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("Sidecar source context has no exact accepted attachment")
                })?;
            anyhow::ensure!(
                attached.event.kind == EventKind::SidecarContextAttach,
                "Sidecar source context revision is not an attachment"
            );
            let payload: arkret_sdk::SidecarContextAttachPayload =
                serde_json::from_value(serde_json::to_value(&attached.event.payload)?)?;
            payload.validate()?;
            anyhow::ensure!(
                payload.sidecar_id == *sidecar_id
                    && payload.source_context_ref == source
                    && attached.event.scope_ref
                        == arkret_sdk::ScopeRef::Sidecar {
                            realm_id: snapshot.realm_id.clone(),
                            sidecar_id: sidecar_id.clone(),
                        }
                    && serde_json::to_value(&attached.event.payload)? == *value,
                "Sidecar source context differs from its accepted attachment"
            );
            for current in &snapshot.current_state_entries {
                let TypedCurrentRow::Value {
                    selector:
                        CurrentSelector::Sidecar {
                            sidecar_id: candidate,
                        },
                    value,
                    ..
                } = current
                else {
                    continue;
                };
                if candidate != sidecar_id {
                    continue;
                }
                let sidecar: arkret_sdk::AgentSidecar = serde_json::from_value(value.clone())?;
                sidecar.validate_shape()?;
                anyhow::ensure!(
                    sidecar.id == *sidecar_id && sidecar.realm_id == snapshot.realm_id,
                    "Sidecar current identity differs from its selector"
                );
                if &sidecar.controller_account_id != controller
                    || attached.event.actor_id.as_account_id() != Some(controller)
                    || sidecar.state == arkret_sdk::AgentSidecarState::Tombstoned
                {
                    continue;
                }
                anyhow::ensure!(
                    found.is_none(),
                    "Source route has multiple controller Sidecars"
                );
                found = Some(sidecar);
            }
        }
        Ok(found)
    }

    pub(crate) fn ingest_verified_sidecar_history(
        &mut self,
        page: &impl crate::transport::own_station_results::AcceptedPageRows,
    ) -> Result<usize, String> {
        if page
            .accepted_account()
            .is_some_and(|account| self.active_authority().as_ref() != Some(account))
        {
            return Err("ordinary accepted page belongs to another account store".into());
        }
        self.ensure_cached_loaded();
        let mut next = self.cached.verified_sidecar_history.clone();
        for row in page.accepted_rows()? {
            let commit = row.commit();
            if !matches!(commit.stream_ref, CommitStreamRef::Sidecar { .. }) {
                continue;
            }
            let key = serde_json::to_string(&commit.stream_ref).map_err(|e| e.to_string())?;
            let rows = next.entry(key).or_default();
            match rows
                .binary_search_by_key(&commit.stream_position, |row| row.commit().stream_position)
            {
                Ok(index) => {
                    if rows[index].commit() != commit {
                        return Err("Sidecar replay forks a held Commit coordinate".into());
                    }
                    match (&rows[index], row) {
                        (CommittedEventView::Full(old), CommittedEventView::Full(new))
                            if old != new =>
                        {
                            return Err("Sidecar replay changes a held Event".into());
                        }
                        _ => rows[index] = row.clone(),
                    }
                }
                Err(index) => rows.insert(index, row.clone()),
            }
        }
        let changed = usize::from(next != self.cached.verified_sidecar_history);
        self.cached.verified_sidecar_history = next;
        Ok(changed)
    }

    /// The private capability can only be constructed after the signed
    /// complete Snapshot and its nonce-bound authority cut have verified.
    pub(crate) fn install_verified_sidecar_current(
        &mut self,
        proof: &crate::realm_events_engine::VerifiedCurrentSnapshot,
    ) -> Result<usize, String> {
        self.install_sidecar_current_original(proof.snapshot())
    }

    pub(crate) fn install_own_station_sidecar_current(
        &mut self,
        response: &arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
            arkret_sdk::RealmId,
            arkret_sdk::RealmStateSnapshot,
        >,
    ) -> Result<usize, String> {
        let incoming = response.value().map_err(|e| e.to_string())?;
        if self.active_authority().as_ref() != Some(response.session().account_id()) {
            return Err("own-Station current belongs to a different account store".into());
        }
        garth::own_station_results::consume_bound_snapshot(response, &incoming.realm_id)
            .map_err(|e| e.to_string())?;
        self.install_sidecar_current_original(incoming)
    }

    fn install_sidecar_current_original(
        &mut self,
        incoming: &arkret_sdk::RealmStateSnapshot,
    ) -> Result<usize, String> {
        self.ensure_cached_loaded();
        let prior = self
            .cached
            .verified_sidecar_current_watermarks
            .get(incoming.realm_id.as_str())
            .cloned()
            .unwrap_or_default();
        let mut generation = prior.governance_generation;
        let mut observed = prior
            .stream_heads
            .into_iter()
            .map(|head| (head.stream_ref.clone(), head))
            .collect::<std::collections::BTreeMap<_, _>>();
        // Seed old stores from their held original without inventing a prefix.
        if let Some(old) = self
            .cached
            .verified_sidecar_current
            .get(incoming.realm_id.as_str())
        {
            generation = generation.max(old.governance_generation);
            for head in &old.visible_stream_heads {
                if observed
                    .get(&head.stream_ref)
                    .is_none_or(|known| known.stream_position < head.stream_position)
                {
                    observed.insert(head.stream_ref.clone(), head.clone());
                }
            }
        }
        if incoming.governance_generation < generation {
            return Err(
                "Sidecar current regresses a previously observed governance generation".into(),
            );
        }
        generation = incoming.governance_generation;
        for head in &incoming.visible_stream_heads {
            if observed.get(&head.stream_ref).is_some_and(|known| {
                head.stream_position < known.stream_position
                    || (head.stream_position == known.stream_position
                        && head.commit_id != known.commit_id)
            }) {
                return Err(
                    "Sidecar current regresses or forks a previously observed hidden stream".into(),
                );
            }
            observed.insert(head.stream_ref.clone(), head.clone());
        }

        if let Some(old) = self
            .cached
            .verified_sidecar_current
            .get(incoming.realm_id.as_str())
        {
            if incoming.governance_generation < old.governance_generation {
                return Err("Sidecar current authority generation regressed".into());
            }
            for old_head in &old.visible_stream_heads {
                if let Some(new_head) = incoming
                    .visible_stream_heads
                    .iter()
                    .find(|head| head.stream_ref == old_head.stream_ref)
                    && (new_head.stream_position < old_head.stream_position
                        || (new_head.stream_position == old_head.stream_position
                            && new_head.commit_id != old_head.commit_id))
                {
                    return Err("Sidecar current Snapshot regresses or forks a held head".into());
                }
            }
        }
        let changed = usize::from(
            self.cached
                .verified_sidecar_current
                .get(incoming.realm_id.as_str())
                != Some(incoming),
        );
        self.cached.verified_sidecar_current_watermarks.insert(
            incoming.realm_id.to_string(),
            super::types::ObservedSidecarCurrentWatermark {
                governance_generation: generation,
                stream_heads: observed.into_values().collect(),
            },
        );
        self.cached
            .verified_sidecar_current
            .insert(incoming.realm_id.to_string(), incoming.clone());
        Ok(changed)
    }

    pub(crate) fn invalidate_sidecar_current(&mut self, realm: Option<&str>) {
        self.ensure_cached_loaded();
        match realm {
            Some(realm) => {
                self.cached.verified_sidecar_current.remove(realm);
            }
            None => self.cached.verified_sidecar_current.clear(),
        }
    }

    /// Completeness is checked against the independent signed current head.
    /// A verified suffix, withheld row or an old current cut is not a fold.
    pub(crate) fn verified_sidecar_inputs(
        &self,
        realm: &str,
    ) -> anyhow::Result<(
        RealmStateSnapshot,
        BTreeMap<String, Vec<arkret_sdk::CommittedEventFullView>>,
    )> {
        let snapshot = self.with_unoverlaid_account_fields(|state| {
            state
                .verified_sidecar_current
                .get(realm)
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Sidecar exchange current requires a verified signed current cut"
                    )
                })
        })?;
        let histories = self.sidecar_history_at_snapshot(&snapshot)?;
        Ok((snapshot, histories))
    }

    /// Select a complete verified prefix at an independently authenticated cut.
    /// Later accepted rows remain cached, but cannot enter this cut's fold.
    pub(crate) fn sidecar_history_at_snapshot(
        &self,
        snapshot: &RealmStateSnapshot,
    ) -> anyhow::Result<BTreeMap<String, Vec<arkret_sdk::CommittedEventFullView>>> {
        self.with_unoverlaid_account_fields(|state| {
            let mut histories = BTreeMap::new();
            for head in &snapshot.visible_stream_heads {
                let CommitStreamRef::Sidecar { sidecar_id, .. } = &head.stream_ref else {
                    continue;
                };
                let key = serde_json::to_string(&head.stream_ref)?;
                let rows = state.verified_sidecar_history.get(&key).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Sidecar exchange current requires verified Sidecar Commit history"
                    )
                })?;
                let mut full_rows = Vec::with_capacity(rows.len());
                let mut previous = None;
                for (position, row) in rows.iter().enumerate() {
                    if row.commit().stream_position > head.stream_position {
                        break;
                    }
                    let CommittedEventView::Full(full) = row else {
                        anyhow::bail!("Sidecar exchange history contains an undisclosed Event");
                    };
                    anyhow::ensure!(
                        full.commit.stream_ref == head.stream_ref
                            && full.commit.stream_position == u64::try_from(position)?
                            && full.commit.previous_commit_ref == previous
                            && full.commit.event_ref == full.event.event_id
                            && full.event.realm_id == snapshot.realm_id,
                        "Sidecar exchange history is not a complete native Commit chain"
                    );
                    previous = Some(full.commit.commit_id.clone());
                    full_rows.push(full.clone());
                }
                anyhow::ensure!(
                    full_rows
                        .last()
                        .is_some_and(|row| row.commit.commit_id == head.commit_id
                            && row.commit.stream_position == head.stream_position),
                    "Sidecar exchange history and signed current head differ"
                );
                histories.insert(sidecar_id.to_string(), full_rows);
            }
            Ok(histories)
        })
    }

    pub(crate) fn has_pending_sidecar_history(&self, realm: &str) -> bool {
        self.with_unoverlaid_account_fields(|state| {
            state
                .verified_sidecar_current
                .get(realm)
                .is_some_and(|snapshot| {
                    snapshot
                        .visible_stream_heads
                        .iter()
                        .any(|head| matches!(head.stream_ref, CommitStreamRef::Sidecar { .. }))
                        && self.sidecar_history_at_snapshot(snapshot).is_err()
                })
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn own_station_current_only_hidden_stream_watermark_survives_reopen_and_rejects_lower_or_fork()
     {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private-current.json");
        let account =
            crate::test_support::AccountFixture::new("did:webvh:z6mkfixture:alice.example")
                .station("ak:did_core:web:station.example")
                .build();
        let mut store = LocalStateStore::with_path(path.clone());
        store.switch_active_account(&account).unwrap();
        let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [8; 32],
        ));
        let realm_stream = arkret_sdk::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let sidecar_stream = arkret_sdk::CommitStreamRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id: arkret_sdk::SidecarId::from_event_id(&arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [9; 32],
            )),
        };
        let realm_head = arkret_sdk::CommitStreamHead {
            stream_ref: realm_stream.clone(),
            stream_position: 0,
            commit_id: arkret_sdk::RealmCommitId::from_digest([1; 32]),
        };
        let initial_head = arkret_sdk::CommitStreamHead {
            stream_ref: sidecar_stream.clone(),
            stream_position: 2,
            commit_id: arkret_sdk::RealmCommitId::from_digest([2; 32]),
        };
        let make = |private: Option<arkret_sdk::CommitStreamHead>, generation| {
            let at = chrono::DateTime::parse_from_rfc3339("2026-10-05T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc);
            let mut heads = vec![realm_head.clone()];
            if let Some(head) = private {
                heads.push(head);
            }
            heads.sort_by(|a, b| a.stream_ref.cmp(&b.stream_ref));
            let mut snapshot = arkret_sdk::RealmStateSnapshot {
                snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
                realm_id: realm.clone(),
                governance_generation: generation,
                retention_and_history_floor: arkret_sdk::RetentionAndHistoryFloor {
                    history_access: arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers,
                    stream_floors: heads
                        .iter()
                        .map(|h| arkret_sdk::StreamHistoryFloor {
                            stream_ref: h.stream_ref.clone(),
                            oldest_position: 0,
                        })
                        .collect(),
                },
                visible_stream_heads: heads,
                current_state_entries: vec![],
                created_at: at,
                signature: arkret_sdk::DetachedObjectSignature {
                    context: arkret_sdk::DetachedSignatureContext::RealmSnapshot,
                    signature_algorithm: arkret_sdk::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: arkret_sdk::DidUrl::new("did:web:station.example#key")
                        .unwrap(),
                    signed_digest: arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64)))
                        .unwrap(),
                    created_at: at,
                    sig: arkret_sdk::Base64UrlString::new("AA").unwrap(),
                },
            };
            let mut unsigned = serde_json::to_value(&snapshot).unwrap();
            unsigned.as_object_mut().unwrap().remove("snapshot_id");
            unsigned.as_object_mut().unwrap().remove("signature");
            snapshot.snapshot_id =
                arkret_sdk::RealmSnapshotId::from_digest(arkret_sdk::canonical::sha256_bytes(
                    arkret_sdk::canonical::canonical_json_bytes(&unsigned).unwrap(),
                ));
            snapshot
        };
        let initial = make(Some(initial_head.clone()), 1);
        let hidden = make(None, 1);
        let lower = make(
            Some(arkret_sdk::CommitStreamHead {
                stream_position: 1,
                ..initial_head.clone()
            }),
            1,
        );
        let fork = make(
            Some(arkret_sdk::CommitStreamHead {
                commit_id: arkret_sdk::RealmCommitId::from_digest([3; 32]),
                ..initial_head.clone()
            }),
            1,
        );
        let forward = make(
            Some(arkret_sdk::CommitStreamHead {
                stream_position: 3,
                commit_id: arkret_sdk::RealmCommitId::from_digest([4; 32]),
                ..initial_head.clone()
            }),
            1,
        );
        let rollback_generation = make(Some(initial_head.clone()), 0);
        let (client, server) = crate::transport::own_station_results::test_http::client(
            &account.authority,
            [
                initial,
                hidden.clone(),
                lower,
                fork,
                rollback_generation,
                forward.clone(),
            ]
            .into_iter()
            .map(|s| serde_json::to_value(s).unwrap())
            .collect(),
        );
        for _ in 0..2 {
            let response = client.snapshot_head(&realm).await.unwrap();
            store
                .verified_projection_transaction(|s| {
                    s.install_own_station_sidecar_current(&response)
                })
                .unwrap();
        }
        assert_eq!(
            store.load().verified_sidecar_current.get(realm.as_str()),
            Some(&hidden)
        );
        // Original exact visible cut stays hidden; the held current watermark
        // is not allowed to become a history cursor or an authoring input.
        assert!(
            store
                .verified_commit_stream_cursor(&sidecar_stream)
                .unwrap()
                .is_none()
        );
        store.flush().unwrap();
        let mut reopened = LocalStateStore::with_path(path);
        reopened.switch_active_account(&account).unwrap();
        reopened.invalidate_sidecar_current(Some(realm.as_str()));
        let original = serde_json::to_value(reopened.load()).unwrap();
        for _ in 0..3 {
            let response = client.snapshot_head(&realm).await.unwrap();
            assert!(
                reopened
                    .verified_projection_transaction(
                        |s| s.install_own_station_sidecar_current(&response)
                    )
                    .is_err()
            );
            assert_eq!(serde_json::to_value(reopened.load()).unwrap(), original);
        }
        let response = client.snapshot_head(&realm).await.unwrap();
        reopened
            .verified_projection_transaction(|s| s.install_own_station_sidecar_current(&response))
            .unwrap();
        assert_eq!(
            reopened.load().verified_sidecar_current.get(realm.as_str()),
            Some(&forward)
        );
        assert!(
            reopened
                .verified_commit_stream_cursor(&sidecar_stream)
                .unwrap()
                .is_none()
        );
        server.join().unwrap();
    }
}
