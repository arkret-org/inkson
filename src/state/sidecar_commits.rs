//! Private replay material, admitted only by the shared signature verifiers.

use std::collections::BTreeMap;

use arkret_sdk::{CommitStreamRef, CommittedEventView, RealmStateSnapshot};

use super::LocalStateStore;

impl LocalStateStore {
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
