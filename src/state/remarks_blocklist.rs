use super::*;

/// A connection-local privacy gate. The accepted list remains durable; freshness
/// cannot survive a lost account subscription or be restored from a disk cache.
#[derive(Debug, Default)]
pub(super) struct BlocklistSyncState {
    scope: String,
    attempt: u64,
    valid: bool,
    caught_up: bool,
}

/// Owns one account catch-up attempt. Dropping an old connection cannot invalidate
/// its replacement, and a stale completion cannot authorize the replacement.
pub struct BlocklistCatchup {
    state: Arc<Mutex<BlocklistSyncState>>,
    scope: String,
    attempt: u64,
}

impl BlocklistCatchup {
    pub(crate) fn finish_checkpoint(
        &self,
        durable: garth::Result<()>,
        reset: bool,
        active: bool,
    ) -> garth::Result<()> {
        if durable.is_err() || reset {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.scope == self.scope && state.attempt == self.attempt {
                state.valid = false;
                state.caught_up = false;
            }
        } else if active {
            self.complete();
        }
        durable
    }

    pub(crate) fn complete(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.scope == self.scope && state.attempt == self.attempt && state.valid {
            state.caught_up = true;
        }
    }
}

impl Drop for BlocklistCatchup {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.scope == self.scope && state.attempt == self.attempt {
            state.caught_up = false;
            state.valid = false;
        }
    }
}

impl LocalStateStore {
    pub(crate) fn begin_blocklist_catchup(&self) -> BlocklistCatchup {
        let scope = self.effective_account_key();
        let mut state = self
            .blocklist_sync
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.attempt = state.attempt.wrapping_add(1);
        state.scope = scope.clone();
        state.valid = true;
        state.caught_up = false;
        BlocklistCatchup {
            state: Arc::clone(&self.blocklist_sync),
            scope,
            attempt: state.attempt,
        }
    }

    pub(crate) fn invalidate_blocklist_freshness(&self) {
        let mut state = self
            .blocklist_sync
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.scope == self.effective_account_key() {
            state.valid = false;
            state.caught_up = false;
        }
    }

    pub fn blocklist_freshness_known(&self) -> bool {
        let state = self
            .blocklist_sync
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.scope == self.effective_account_key() && state.valid && state.caught_up
    }

    /// A local-only refusal, before stream-head lookup, nonce allocation or HTTP.
    pub fn require_blocklist_signal_freshness(
        &self,
        payload: &crate::signal::SignalPayload,
    ) -> anyhow::Result<()> {
        if matches!(
            payload,
            crate::signal::SignalPayload::Presence { .. }
                | crate::signal::SignalPayload::ReadReceipt { .. }
                | crate::signal::SignalPayload::Typing { .. }
        ) {
            anyhow::ensure!(
                self.blocklist_freshness_known(),
                "blocklist freshness is unknown; privacy Signal withheld"
            );
        }
        Ok(())
    }

    /// Return the stored remark for `realm_id`, if any. `None` means the
    /// user has not set a local override and the public Realm title
    /// should be rendered.
    pub fn realm_remark(&self, realm_id: &str) -> Option<crate::account_data::RealmRemark> {
        self.load().realm_remarks.get(realm_id).cloned()
    }

    /// All known Realm remarks. The settings UI uses this to render the
    /// edit list; callers MUST NOT publish this map to other Realm
    /// members — it is actor-private per §3.7.
    pub fn realm_remarks(&self) -> BTreeMap<String, crate::account_data::RealmRemark> {
        self.load().realm_remarks
    }

    /// Upsert a remark for `realm_id`. Passing a remark whose
    /// [`RealmRemark::is_empty`] returns true tombstones the entry
    /// (equivalent to `remove_realm_remark`). Persists synchronously to
    /// disk; the caller is responsible for pushing the same payload to
    /// coland via `ak.account_data.set`.
    pub fn set_realm_remark(
        &mut self,
        realm_id: impl Into<String>,
        remark: crate::account_data::RealmRemark,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        if remark.is_empty() {
            self.cached.realm_remarks.remove(&realm_id);
        } else {
            self.cached.realm_remarks.insert(realm_id, remark);
        }
        let _ = self.flush();
    }

    /// Delete the remark for `realm_id`. No-op if none is stored.
    pub fn remove_realm_remark(&mut self, realm_id: &str) {
        self.ensure_cached_loaded();
        self.cached.realm_remarks.remove(realm_id);
        let _ = self.flush();
    }

    // ── Contact remarks (spec client-preferences.md §3.6) ─

    /// Rebuild the transient holder-private labels before resuming a saved
    /// Account cursor. The encrypted accepted Events are already retained;
    /// an up-to-date cursor need not deliver them again after process restart.
    pub(crate) fn restore_contact_remarks_from_retained_account_data(
        &mut self,
        authority: &arkret_sdk::AccountId,
    ) -> usize {
        if self.active_authority().as_ref() != Some(authority) {
            return 0;
        }
        self.ensure_cached_loaded();
        if self.contact_remarks_restored_for.as_ref() == Some(authority) {
            return 0;
        }
        let Ok(namespace_key) = crate::account_data::account_data_namespace_key(authority) else {
            // A locked account is restored by the existing unlock flow.
            return 0;
        };
        let mut restored = 0;
        for event in self.current_account_data_events() {
            if event.kind.as_str() != "ak.account_data.set"
                || event.actor_id != arkret_sdk::ActorId::account(authority.clone())
            {
                continue;
            }
            let Some(key) = event.payload.get("key").and_then(Value::as_str) else {
                continue;
            };
            if crate::account_data::principal_key_from_contact_remark_key(key).is_none() {
                continue;
            }
            let remark =
                crate::account_data::decrypt_account_data_entry(authority, key, &event.payload)
                    .and_then(|body| {
                        serde_json::from_value::<crate::account_data::ContactRemark>(body)
                            .map_err(Into::into)
                    });
            let Ok(remark) = remark else {
                continue;
            };
            if remark.is_empty()
                || remark
                    .validate_for_account_data_key(&namespace_key, key)
                    .is_err()
            {
                continue;
            }
            // A local writer may have accepted a newer value before its Account
            // delta arrives. Retained older evidence cannot overwrite it.
            if let std::collections::btree_map::Entry::Vacant(slot) = self
                .cached
                .contact_remarks
                .entry(remark.subject.principal_id.to_string())
            {
                slot.insert(remark);
                restored += 1;
            }
        }
        self.contact_remarks_restored_for = Some(authority.clone());
        restored
    }

    pub fn contact_remark(&self, actor_id: &str) -> Option<crate::account_data::ContactRemark> {
        self.load().contact_remarks.get(actor_id).cloned()
    }

    pub fn contact_remarks(&self) -> BTreeMap<String, crate::account_data::ContactRemark> {
        self.load().contact_remarks
    }

    /// Replace the transient eligibility projection used by live labels.
    /// Only accepted human Contacts contribute a canonical principal.
    pub fn replace_accepted_human_contacts(&mut self, contacts: &[crate::models::ContactListRow]) {
        self.ensure_cached_loaded();
        let mut changed = false;
        for contact in contacts {
            if let Some(summary) = &contact.direct_conversation {
                let peer = contact.peer.clone();
                changed |= self
                    .cached
                    .direct_conversation_peers
                    .insert(summary.realm_id.to_string(), peer.clone())
                    .as_ref()
                    != Some(&peer);
            }
            for agent in &contact.contact_agent_projections {
                if let Some(summary) = &agent.direct_conversation {
                    let peer = arkret_sdk::contact_operations::ContactPeer::Agent {
                        actor_id: agent.actor_id.clone(),
                        controller_account_id: agent.controller_account_id.clone(),
                    };
                    changed |= self
                        .cached
                        .direct_conversation_peers
                        .insert(summary.realm_id.to_string(), peer.clone())
                        .as_ref()
                        != Some(&peer);
                }
            }
        }
        self.cached.accepted_human_contact_principals = contacts
            .iter()
            .filter(|contact| contact.state == crate::models::ContactState::Accepted)
            .filter_map(|contact| match &contact.peer {
                arkret_sdk::contact_operations::ContactPeer::Human { account_id } => {
                    Some(account_id.principal_id.to_string())
                }
                arkret_sdk::contact_operations::ContactPeer::Agent { .. } => None,
            })
            .collect();
        if changed {
            let _ = self.flush();
        }
    }

    pub fn is_accepted_human_contact(&self, principal_id: &str) -> bool {
        self.load()
            .accepted_human_contact_principals
            .contains(principal_id)
    }

    /// A retained record is active as a live label only while its subject is
    /// still present in the accepted-human Contact projection.
    pub fn active_contact_remark(
        &self,
        principal_id: &str,
    ) -> Option<crate::account_data::ContactRemark> {
        self.is_accepted_human_contact(principal_id)
            .then(|| self.contact_remark(principal_id))
            .flatten()
    }

    pub fn active_contact_remarks(&self) -> BTreeMap<String, crate::account_data::ContactRemark> {
        let state = self.load();
        state
            .contact_remarks
            .into_iter()
            .filter(|(principal_id, _)| {
                state
                    .accepted_human_contact_principals
                    .contains(principal_id)
            })
            .collect()
    }

    pub fn set_contact_remark(
        &mut self,
        actor_id: impl Into<String>,
        remark: crate::account_data::ContactRemark,
    ) {
        self.ensure_cached_loaded();
        if let Some(authority) = self.active_authority() {
            self.restore_contact_remarks_from_retained_account_data(&authority);
        }
        let actor_id = actor_id.into();
        if remark.is_empty() {
            self.cached.contact_remarks.remove(&actor_id);
        } else {
            self.cached.contact_remarks.insert(actor_id, remark);
        }
        let _ = self.flush();
    }

    /// Apply an opaque physical-delete tombstone received from another device.
    /// The server cannot name the principal, so match the slot by recomputing
    /// keys only over the holder's bounded local Contact remark set.
    pub fn remove_contact_remark_by_storage_key(
        &mut self,
        namespace_key: &[u8],
        storage_key: &str,
    ) -> bool {
        self.ensure_cached_loaded();
        let principal_id = self
            .cached
            .contact_remarks
            .keys()
            .find(|principal_id| {
                arkret_sdk::DidCoreId::new(principal_id.as_str())
                    .ok()
                    .and_then(|principal_id| {
                        crate::account_data::contact_remark_account_data_key(
                            namespace_key,
                            &principal_id,
                        )
                        .ok()
                    })
                    .as_deref()
                    == Some(storage_key)
            })
            .cloned();
        let removed = principal_id
            .as_deref()
            .and_then(|principal_id| self.cached.contact_remarks.remove(principal_id))
            .is_some();
        if removed {
            let _ = self.flush();
        }
        removed
    }

    /// Reconcile against a complete Account Data projection. Physical deletes
    /// may be represented by absence rather than an inline tombstone.
    pub fn retain_contact_remarks_for_storage_keys(
        &mut self,
        namespace_key: &[u8],
        live_storage_keys: &BTreeSet<String>,
    ) {
        self.ensure_cached_loaded();
        self.cached.contact_remarks.retain(|principal_id, _| {
            arkret_sdk::DidCoreId::new(principal_id.as_str())
                .ok()
                .and_then(|principal_id| {
                    crate::account_data::contact_remark_account_data_key(
                        namespace_key,
                        &principal_id,
                    )
                    .ok()
                })
                .is_some_and(|storage_key| live_storage_keys.contains(&storage_key))
        });
    }

    // ── Personal blocklist (spec client-preferences.md "ak.account.blocklist") ─

    /// Current personal blocklist. Cheap clone — the underlying `Vec`
    /// is short by design (curated by the user).
    pub fn client_blocklist(
        &self,
    ) -> Vec<arkret_models_collaboration::objects::productivity::AccountBlocklistEntry> {
        self.load().client_blocklist
    }

    pub fn client_blocklist_revision(&self) -> u64 {
        self.load().client_blocklist_revision
    }

    /// Return the bounded, revision-keyed projection for one exact sender.
    /// Entries are still evaluated for mode/surface/expiry by the caller; the
    /// cache only avoids repeatedly scanning the full holder-private list.
    pub fn client_blocklist_for_actor(
        &self,
        actor_id: &str,
    ) -> Vec<arkret_models_collaboration::objects::productivity::AccountBlocklistEntry> {
        let Ok(actor) = serde_json::from_str::<arkret_sdk::ActorId>(actor_id) else {
            return Vec::new();
        };
        let actor_key = actor.to_string();
        let state = self.load();
        let mut cache = self
            .blocklist_projection_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.revision != Some(state.client_blocklist_revision) {
            cache.revision = Some(state.client_blocklist_revision);
            cache.by_actor.clear();
        }
        if let Some(entries) = cache.by_actor.get(&actor_key) {
            return entries.clone();
        }
        let entries = state
            .client_blocklist
            .into_iter()
            .filter(|entry| {
                matches!(
                    &entry.target,
                    arkret_models_collaboration::objects::productivity::AccountBlocklistTarget::Actor(target)
                        if target.actor_id == actor
                )
            })
            .collect::<Vec<_>>();
        if cache.by_actor.len() >= BLOCKLIST_PROJECTION_CACHE_MAX_ACTORS
            && let Some(oldest_key) = cache.by_actor.keys().next().cloned()
        {
            cache.by_actor.remove(&oldest_key);
        }
        cache.by_actor.insert(actor_key, entries.clone());
        entries
    }

    fn invalidate_blocklist_projection_cache(&self) {
        let mut cache = self
            .blocklist_projection_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.revision = None;
        cache.by_actor.clear();
    }

    #[cfg(test)]
    pub(crate) fn blocklist_projection_cache_len(&self) -> usize {
        self.blocklist_projection_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .by_actor
            .len()
    }

    /// Append `actor_id` to the personal blocklist. Idempotent — duplicate
    /// actor IDs are not inserted twice. `reason` is shown back to the user
    /// in Settings → Privacy; pass `None` to skip.
    ///
    /// Persists synchronously to disk; the caller is responsible for
    /// pushing the new list to coland via
    /// `ak.account_data.set("ak.account.blocklist", …)`.
    pub fn block_user(&mut self, actor_id: impl AsRef<str>, reason: Option<String>) -> bool {
        let Ok(actor) = serde_json::from_str::<arkret_sdk::ActorId>(actor_id.as_ref()) else {
            return false;
        };
        let actor_key = actor.to_string();
        self.ensure_cached_loaded();
        let changed = crate::account_data::block_user_in(
            &mut self.cached.client_blocklist,
            &actor_key,
            reason,
            chrono::Utc::now(),
        );
        if changed {
            self.cached.pending_personal_block_sagas.insert(actor_key);
            self.cached.personal_blocklist_write_pending = true;
            self.invalidate_blocklist_projection_cache();
            let _ = self.flush();
        }
        changed
    }

    /// Remove every entry for `actor_id` from the personal blocklist.
    /// Returns `true` when at least one entry was removed.
    pub fn unblock_user(&mut self, actor_id: impl AsRef<str>) -> bool {
        self.ensure_cached_loaded();
        let changed = crate::account_data::unblock_user_in(
            &mut self.cached.client_blocklist,
            actor_id.as_ref(),
        );
        if changed {
            self.cached.personal_blocklist_write_pending = true;
            self.invalidate_blocklist_projection_cache();
            let _ = self.flush();
        }
        changed
    }

    /// Append a typed block exposed by this UI (`kind` ∈ actor / domain)
    /// to the personal blocklist. Idempotent per `(kind, value)` pair.
    /// `applies_to` lists the surfaces the block covers (empty = all default
    /// surfaces); `expires_at` is an optional RFC 3339 expiry. Same
    /// persistence + push contract as [`block_user`].
    pub fn block_target(
        &mut self,
        kind: crate::account_data::BlocklistUiTargetKind,
        value: impl AsRef<str>,
        reason: Option<String>,
        applies_to: Vec<
            arkret_models_collaboration::objects::productivity::AccountBlocklistSurface,
        >,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> bool {
        let actor = if kind == crate::account_data::BlocklistUiTargetKind::Actor {
            let Ok(actor) = serde_json::from_str::<arkret_sdk::ActorId>(value.as_ref()) else {
                return false;
            };
            Some(actor)
        } else {
            None
        };
        self.ensure_cached_loaded();
        let changed = crate::account_data::block_target_in(
            &mut self.cached.client_blocklist,
            kind,
            value.as_ref(),
            reason,
            applies_to,
            expires_at,
            chrono::Utc::now(),
        );
        if changed {
            if let Some(actor) = actor
                && self.cached.client_blocklist.iter().any(|entry| {
                    crate::account_data::requires_contact_tombstone(
                        std::slice::from_ref(entry),
                        &actor.to_string(),
                        chrono::Utc::now(),
                    )
                })
            {
                self.cached
                    .pending_personal_block_sagas
                    .insert(actor.to_string());
            }
            self.cached.personal_blocklist_write_pending = true;
            self.invalidate_blocklist_projection_cache();
            let _ = self.flush();
        }
        changed
    }

    /// Remove the `(kind, value)` block from the personal blocklist. Returns
    /// `true` when an entry was removed. Prefer this over [`unblock_user`] on
    /// surfaces that track the target kind.
    pub fn unblock_target(
        &mut self,
        target: &arkret_models_collaboration::objects::productivity::AccountBlocklistTarget,
    ) -> bool {
        self.ensure_cached_loaded();
        let changed =
            crate::account_data::unblock_target_in(&mut self.cached.client_blocklist, target);
        if changed {
            self.cached.personal_blocklist_write_pending = true;
            self.invalidate_blocklist_projection_cache();
            let _ = self.flush();
        }
        changed
    }

    /// Replace the whole personal blocklist from `/sync account_data`.
    /// User edits still go through [`block_user`] / [`unblock_user`];
    /// this method is only for remote state hydration.
    pub fn set_client_blocklist(
        &mut self,
        revision: u64,
        entries: Vec<arkret_models_collaboration::objects::productivity::AccountBlocklistEntry>,
    ) {
        self.ensure_cached_loaded();
        if revision < self.cached.client_blocklist_revision
            || (revision == self.cached.client_blocklist_revision
                && self.cached.client_blocklist != entries)
        {
            return;
        }
        self.cached.client_blocklist = entries;
        self.cached.client_blocklist_revision = revision;
        self.reconcile_personal_block_sagas_after_accepted_write();
        self.invalidate_blocklist_projection_cache();
        let _ = self.flush();
    }

    pub fn pending_personal_block_sagas(&self) -> BTreeSet<String> {
        self.load().pending_personal_block_sagas
    }

    pub fn committed_personal_block_sagas(&self) -> BTreeSet<String> {
        self.load().committed_personal_block_sagas
    }

    pub fn personal_blocklist_write_pending(&self) -> bool {
        let state = self.load();
        state.personal_blocklist_write_pending
            || state
                .pending_personal_block_sagas
                .iter()
                .any(|peer| !state.committed_personal_block_sagas.contains(peer))
    }

    /// Advance the durable saga boundary after Account Data accepted the exact
    /// current full-list value. A successor that removed or narrowed a block
    /// cancels its not-yet-committed Contact leg; live DM blocks resume at the
    /// holder tombstone without writing another Account Data revision.
    pub fn mark_personal_blocklist_sagas_committed(&mut self) {
        self.ensure_cached_loaded();
        self.reconcile_personal_block_sagas_after_accepted_write();
        let _ = self.flush();
    }

    fn reconcile_personal_block_sagas_after_accepted_write(&mut self) {
        self.cached.personal_blocklist_write_pending = false;
        let entries = &self.cached.client_blocklist;
        let now = chrono::Utc::now();
        let peers = self
            .cached
            .pending_personal_block_sagas
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for peer in peers {
            if crate::account_data::requires_contact_tombstone(entries, &peer, now) {
                self.cached.committed_personal_block_sagas.insert(peer);
            } else {
                self.cached.pending_personal_block_sagas.remove(&peer);
                self.cached.committed_personal_block_sagas.remove(&peer);
            }
        }
    }

    pub fn complete_personal_block_saga(&mut self, peer_id: &str) {
        self.ensure_cached_loaded();
        let pending_removed = self.cached.pending_personal_block_sagas.remove(peer_id);
        let committed_removed = self.cached.committed_personal_block_sagas.remove(peer_id);
        if pending_removed || committed_removed {
            let _ = self.flush();
        }
    }

    /// Best-effort name for `realm_id`: trimmed `local_name` from the
    /// stored remark if set, otherwise `public_title`. Mirrors the §3.7
    /// "UI MUST prefer local_name" rule so the sidebar / dashboard /
    /// dashboard cards all agree.
    pub fn display_name_for_realm(&self, realm_id: &str, public_title: &str) -> String {
        match self
            .load()
            .realm_remarks
            .get(realm_id)
            .map(|r| r.display_name(public_title).to_owned())
        {
            Some(name) => name,
            None => public_title.to_owned(),
        }
    }

    /// Read cursor for one independent commit stream.
    ///
    /// Absence means this device has verified nothing on that stream yet;
    /// callers must scan from the start rather than assume a position.
    pub fn stream_head(
        &self,
        stream_ref: &arkret_wire::CommitStreamRef,
    ) -> Option<arkret_wire::CommitStreamHead> {
        let key = commit_stream_key(stream_ref)?;
        self.load().stream_cursors.get(&key).cloned()
    }

    /// Advance one stream's cursor. A head that does not strictly advance the
    /// stored position is ignored: commit streams are linear and monotone, and
    /// a backwards head would re-open already-verified positions.
    pub fn record_stream_head(&mut self, head: arkret_wire::CommitStreamHead) -> bool {
        self.ensure_cached_loaded();
        let Some(key) = commit_stream_key(&head.stream_ref) else {
            return false;
        };
        if let Some(current) = self.cached.stream_cursors.get(&key)
            && current.stream_position >= head.stream_position
        {
            return false;
        }
        self.cached.stream_cursors.insert(key, head);
        let _ = self.flush();
        true
    }

    /// Every commit-stream cursor this device holds, keyed by
    /// [`commit_stream_key`]. There is deliberately no aggregate position.
    pub fn stream_heads(&self) -> BTreeMap<String, arkret_wire::CommitStreamHead> {
        self.load().stream_cursors
    }

    /// Verified current governance authority for a Realm, when one has been
    /// established. `None` means authority is unknown and every authority-bound
    /// decision must fail closed.
    pub fn realm_authority_basis(&self, realm_id: &str) -> Option<PersistedRealmAuthorityBasis> {
        self.load().realm_authority_basis.get(realm_id).cloned()
    }

    /// Install the outcome of validating a nonce-bound `RealmAuthorityBundle`.
    /// A lower generation never overwrites a higher one: authority generations
    /// are monotone, so an older bundle is stale evidence, not a handoff back.
    pub fn record_realm_authority_basis(&mut self, basis: PersistedRealmAuthorityBasis) -> bool {
        self.ensure_cached_loaded();
        let key = basis.realm_id.to_string();
        if let Some(current) = self.cached.realm_authority_basis.get(&key)
            && current.current_generation > basis.current_generation
        {
            return false;
        }
        self.cached.realm_authority_basis.insert(key, basis);
        let _ = self.flush();
        true
    }
}

#[cfg(test)]
mod blocklist_freshness_tests {
    use super::*;

    fn store() -> (tempfile::TempDir, LocalStateStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalStateStore::with_path(directory.path().join("state.json"));
        (directory, store)
    }

    #[test]
    fn blocklist_freshness_is_connection_local_and_shared_with_clones() {
        let (_directory, store) = store();
        let clone = store.clone();
        assert!(!store.blocklist_freshness_known());
        let first = store.begin_blocklist_catchup();
        first.complete();
        assert!(store.blocklist_freshness_known());
        assert!(clone.blocklist_freshness_known());
        let second = clone.begin_blocklist_catchup();
        assert!(!store.blocklist_freshness_known());
        first.complete();
        assert!(!store.blocklist_freshness_known());
        drop(first);
        second.complete();
        assert!(store.blocklist_freshness_known());
        drop(second);
        assert!(!clone.blocklist_freshness_known());
    }

    #[test]
    fn blocklist_freshness_is_not_restored_from_retained_account_data() {
        let (directory, mut store) = store();
        store.set_client_blocklist(7, Vec::new());
        let catchup = store.begin_blocklist_catchup();
        catchup.complete();
        assert!(store.blocklist_freshness_known());
        let restored = LocalStateStore::with_path(directory.path().join("state.json"));
        assert_eq!(restored.client_blocklist_revision(), 7);
        assert!(!restored.blocklist_freshness_known());
    }

    #[test]
    fn malformed_blocklist_prevents_catchup_from_authorizing_signals() {
        use arkret_models_collaboration::sync_frames::account_subscribe::{
            AccountSubscribeSnapshotResult, SyncRequestBody,
        };
        use base64::Engine as _;
        let (directory, mut store) = store();
        store.set_client_blocklist(7, Vec::new());
        let authority = crate::test_support::authority(&format!(
            "did:web:blocklist-{}.example",
            crate::operation::uuid_v7()
        ));
        let secure = crate::secure_key_store::default_secure_key_store("inkson");
        crate::mls::runtime::store_account_mls_secret(
            secure.as_ref(),
            &authority,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
        )
        .unwrap();
        let scope = garth::CursorScope::Account {
            service_id: None,
            actor_id: arkret_sdk::ActorId::account(authority.clone()),
            device_id: arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
                .unwrap(),
        };
        let old = garth::AccountCursorCheckpoint {
            cursor: "ak:cursor:before-malformed".into(),
            station_cas: garth::StationCasProjection::default(),
        };
        store.save_account_checkpoint(&scope, old.clone()).unwrap();
        let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let mut entry: arkret_sdk::Event = serde_json::from_value(serde_json::json!({
            "event_id": "ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "kind": "ak.account_data.set", "realm_id": realm,
            "scope_ref": {"kind": "realm", "realm_id": realm},
            "actor_id": arkret_sdk::ActorId::account(authority.clone()),
            "created_at": "2026-09-27T00:00:00.000Z",
            "payload": {"key": "ak.account.blocklist", "expected_server_revision": 7, "body": {}}
        }))
        .unwrap();
        for repaired in [false, false, true] {
            // Reload/reconnect uses the previous durable cursor. A rejected
            // Delta cannot turn into an empty resumed catch-up after restart.
            store = LocalStateStore::with_path(directory.path().join("state.json"));
            assert_eq!(
                store.load_account_checkpoint(&scope).unwrap(),
                Some(old.clone())
            );
            let catchup = store.begin_blocklist_catchup();
            let request = SyncRequestBody {
                after: Some(old.cursor.clone()),
                catchup: Some(true),
                filter: None,
                realm_list: None,
                replace_filter: None,
            };
            if repaired {
                *entry.payload.get_mut("body").unwrap() =
                    crate::account_data::encrypt_account_data_value(
                        &authority,
                        "ak.account.blocklist",
                        &serde_json::json!({"entries":[]}),
                    )
                    .unwrap();
            }
            let mut folder = arkret_sdk::AccountSubscribeFolder::for_request(&request);
            folder.push(serde_json::from_value(serde_json::json!({"kind":"delta","cursor":"ak:cursor:repair-delta","partial":false,"account_data":{"events":[entry.clone()]}})).unwrap()).unwrap();
            folder.push(serde_json::from_value(serde_json::json!({"kind":"catchup_complete","cursor":"ak:cursor:repair-complete"})).unwrap()).unwrap();
            let AccountSubscribeSnapshotResult::Batch(batch) = folder.finish().unwrap() else {
                panic!("validated batch required")
            };
            let checkpoint = garth::AccountCursorCheckpoint {
                cursor: batch.cursor.clone(),
                station_cas: garth::StationCasProjection::default(),
            };
            let durable = store
                .verified_projection_transaction(|store| {
                    for frame in &batch.frames {
                        crate::sync_engine::apply_account_data_entries(
                            store,
                            &frame.account_data.as_ref().unwrap().events,
                            &authority,
                        )
                        .map_err(|error| error.to_string())?;
                    }
                    store
                        .save_account_checkpoint(&scope, checkpoint.clone())
                        .map_err(|error| error.to_string())
                })
                .map_err(garth::Error::Protocol);
            let result = catchup.finish_checkpoint(durable, false, true);
            assert_eq!(result.is_ok(), repaired);
            assert_eq!(store.blocklist_freshness_known(), repaired);
            assert_eq!(
                store.client_blocklist_revision(),
                if repaired { 8 } else { 7 }
            );
            assert_eq!(
                LocalStateStore::with_path(directory.path().join("state.json"))
                    .load_account_checkpoint(&scope)
                    .unwrap(),
                Some(if repaired { checkpoint } else { old.clone() })
            );
        }
    }

    #[test]
    fn blocklist_retained_revision_filters_exact_account_and_rebuilds_after_unblock() {
        let (_directory, mut store) = store();
        let peer = crate::test_support::account_actor("did:web:blocklist-peer.example");
        let other_station =
            arkret_sdk::ActorId::account(crate::test_support::authority_at_station(
                "did:web:blocklist-peer.example",
                "did:web:other-station.example",
            ));
        let entry = crate::account_data::new_blocklist_entry(
            crate::account_data::BlocklistUiTargetKind::Actor, &peer.to_string(), None,
            vec![arkret_models_collaboration::objects::productivity::AccountBlocklistSurface::Messages],
            None, chrono::Utc::now(),
        ).unwrap();
        store.set_client_blocklist(7, vec![entry]);
        assert!(crate::account_data::is_blocked(
            &store.client_blocklist_for_actor(&peer.to_string()),
            &peer.to_string()
        ));
        assert!(!crate::account_data::is_blocked(
            &store.client_blocklist_for_actor(&other_station.to_string()),
            &other_station.to_string()
        ));
        store.set_client_blocklist(6, Vec::new());
        assert_eq!(store.client_blocklist_revision(), 7);
        assert!(crate::account_data::is_blocked(
            &store.client_blocklist_for_actor(&peer.to_string()),
            &peer.to_string()
        ));
        store.set_client_blocklist(8, Vec::new());
        assert_eq!(store.client_blocklist_revision(), 8);
        assert!(!crate::account_data::is_blocked(
            &store.client_blocklist_for_actor(&peer.to_string()),
            &peer.to_string()
        ));
    }
}
