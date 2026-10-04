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
        use arkret_sdk::{CurrentSelector, EventKind, SidecarContextRef, TypedCurrentResult};
        let (snapshot, histories) = self.verified_sidecar_inputs(realm)?;
        let source = SidecarContextRef::Strand {
            strand_id: strand.clone(),
        };
        let mut found = None;
        for row in &snapshot.current_state_entries {
            let TypedCurrentResult::Value {
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
                let TypedCurrentResult::Value {
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
        page: &garth::VerifiedScanPage,
    ) -> Result<usize, String> {
        self.ensure_cached_loaded();
        let mut next = self.cached.verified_sidecar_history.clone();
        for row in page.rows() {
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
        let incoming = proof.snapshot();
        self.ensure_cached_loaded();
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
        let state = self.load();
        let snapshot = state
            .verified_sidecar_current
            .get(realm)
            .ok_or_else(|| {
                anyhow::anyhow!("Sidecar exchange current requires a verified signed current cut")
            })?
            .clone();
        let mut histories = BTreeMap::new();
        for head in &snapshot.visible_stream_heads {
            let CommitStreamRef::Sidecar { sidecar_id, .. } = &head.stream_ref else {
                continue;
            };
            let key = serde_json::to_string(&head.stream_ref)?;
            let rows = state.verified_sidecar_history.get(&key).ok_or_else(|| {
                anyhow::anyhow!("Sidecar exchange current requires verified Sidecar Commit history")
            })?;
            let mut full_rows = Vec::with_capacity(rows.len());
            let mut previous = None;
            for (position, row) in rows.iter().enumerate() {
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
                rows.last()
                    .is_some_and(|row| row.commit().commit_id == head.commit_id
                        && row.commit().stream_position == head.stream_position),
                "Sidecar exchange history and signed current head differ"
            );
            histories.insert(sidecar_id.to_string(), full_rows);
        }
        Ok((snapshot, histories))
    }
}
