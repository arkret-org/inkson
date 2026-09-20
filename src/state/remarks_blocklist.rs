use super::*;

impl LocalStateStore {
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
    /// soland via `ak.account_data.set`.
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
    ) -> Vec<arkret_models_collaboration::objects::productivity::AccountBlocklistPayloadEntry> {
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
    ) -> Vec<arkret_models_collaboration::objects::productivity::AccountBlocklistPayloadEntry> {
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
    /// pushing the new list to soland via
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
        entries: Vec<
            arkret_models_collaboration::objects::productivity::AccountBlocklistPayloadEntry,
        >,
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
