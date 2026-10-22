use super::*;

impl LocalStateStore {
    /// Non-secret trust metadata for the exact active account. Never clone
    /// unrelated replay history to validate one IdentityLink's domain.
    pub(crate) fn server_trust_domain(&self) -> Option<String> {
        self.with_unoverlaid_account_fields(|state| state.server_trust_domain.clone())
    }

    /// Borrow fields untouched by receive-chain overlays when the loaded cache
    /// still belongs to the active account. A namespace mismatch must take the
    /// same persistence path as `load`, never read the previous account's cache.
    pub(crate) fn with_unoverlaid_account_fields<R>(
        &self,
        read: impl FnOnce(&ClientLocalState) -> R,
    ) -> R {
        if self.loaded.load(Ordering::Relaxed)
            && self.cached_account_key.as_deref() == Some(self.effective_account_key().as_str())
        {
            read(&self.cached)
        } else {
            read(&self.load())
        }
    }

    /// Read receive-managed fields without cloning unrelated account state.
    /// Callers explicitly apply overlay precedence to the fields they inspect.
    pub(super) fn with_mls_receive_fields<R>(
        &self,
        read: impl FnOnce(&ClientLocalState, &MlsReceiveOverlay) -> R,
    ) -> R {
        if self.loaded.load(Ordering::Relaxed)
            && self.cached_account_key.as_deref() == Some(self.effective_account_key().as_str())
        {
            read(&self.cached, &self.lock_mls_receive_overlay())
        } else {
            read(&self.load(), &MlsReceiveOverlay::default())
        }
    }

    pub(crate) fn set_product_current_demand(
        &self,
        authority: &arkret_sdk::AccountId,
        realm: &str,
        strands: Option<Vec<arkret_sdk::StrandId>>,
        mut selectors: Vec<arkret_wire::CurrentSelector>,
    ) {
        let mut demand = self
            .product_current_demand
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(mut strands) = strands {
            strands.sort();
            strands.dedup();
            selectors.sort_by_key(|selector| serde_json::to_string(selector).unwrap_or_default());
            selectors.dedup();
            assert!(strands.len() <= 32, "product demand exceeds protocol bound");
            assert!(
                selectors.len() <= 256,
                "product current-selector demand exceeds local bound"
            );
            *demand = Some((authority.clone(), realm.to_owned(), strands, selectors));
        } else if demand
            .as_ref()
            .is_some_and(|(a, r, ..)| a == authority && r == realm)
        {
            *demand = None;
        }
    }

    pub(crate) fn realm_tree_projection(&self, realm_id: &str) -> Option<Value> {
        self.with_unoverlaid_account_fields(|state| {
            state.realm_tree_projections.get(realm_id).cloned()
        })
    }

    /// Install the selected Realm's product view read from the durable
    /// current index. The rows stay in memory; only the profile title and
    /// summary are copied into the stored Realm projection.
    pub(crate) fn install_current_product_view(
        &mut self,
        view: crate::current_projection::RealmCurrentView,
    ) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        let account_key = self.cached_account_key.clone();
        let required_ready = view.ready();
        if let Some(projection) = self.cached.realm_tree_projections.get(&view.realm_id) {
            let mut updated = projection.clone();
            crate::current_projection::apply_profile_summary(&mut updated, &view.entries)?;
            if &updated != projection {
                self.cached
                    .realm_tree_projections
                    .insert(view.realm_id.clone(), updated);
                self.flush()?;
            }
        }
        *self.current_view.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(super::CurrentProductView {
                account_key,
                generation: self.current_generation(),
                view,
                required_ready,
            });
        Ok(())
    }

    /// Forget the in-memory product view, for example after a reset, so no
    /// reader keeps serving rows of a durable generation that was dropped.
    pub(crate) fn clear_current_product_view(&self) {
        *self.current_view.lock().unwrap_or_else(|p| p.into_inner()) = None;
        *self
            .realm_security_view
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
    }

    /// Install presentation evidence read from this account's committed index.
    pub(crate) fn install_realm_security_view(
        &mut self,
        account: &arkret_sdk::AccountId,
        generation: u64,
        states: BTreeMap<String, Option<bool>>,
    ) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        anyhow::ensure!(
            self.active_authority().as_ref() == Some(account),
            "Realm security account changed"
        );
        anyhow::ensure!(
            self.current_generation() == generation,
            "Realm security generation changed"
        );
        let account_key = self.effective_account_key();
        *self
            .realm_security_view
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(super::RealmSecurityView {
            account_key,
            generation,
            states,
        });
        Ok(())
    }

    pub(crate) fn realm_security_states(&self) -> BTreeMap<String, Option<bool>> {
        let key = self.effective_account_key();
        if self.cached_account_key.as_deref() != Some(key.as_str()) {
            return BTreeMap::new();
        }
        self.realm_security_view
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .filter(|view| view.account_key == key && view.generation == self.current_generation())
            .map(|view| view.states.clone())
            .unwrap_or_default()
    }

    /// Cheap account-scoped dependency for readers of the complete product view.
    pub(crate) fn current_product_view_stamp(&self, realm_id: &str) -> Option<(String, u64)> {
        if self.cached_account_key.as_deref() != Some(self.effective_account_key().as_str())
            || self.account_scope_read_denied(realm_id)
        {
            return None;
        }
        self.current_view
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .filter(|view| {
                view.account_key == self.cached_account_key
                    && view.view.realm_id == realm_id.trim()
                    && view.required_ready
                    && view.view.ready()
            })
            .and_then(|view| Some((view.account_key.clone()?, view.generation)))
    }

    /// The installed product view of the active account, if any.
    pub(crate) fn current_product_view(
        &self,
    ) -> Option<crate::current_projection::RealmCurrentView> {
        if self.cached_account_key.as_deref() != Some(self.effective_account_key().as_str()) {
            return None;
        }
        self.current_view
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .filter(|view| view.account_key == self.cached_account_key)
            .map(|view| view.view.clone())
    }

    /// Receipt rendering must retract old hints while the accepted generation
    /// advances or the selected account's product view is being refreshed.
    pub(crate) fn current_read_receipt_policy(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> anyhow::Result<arkret_sdk::ReadReceiptPolicy> {
        anyhow::ensure!(
            !self.current_reset_required()
                && self.cached_account_key.as_deref()
                    == Some(self.effective_account_key().as_str()),
            "receipt-policy account view is unavailable"
        );
        let current = self.current_view.lock().unwrap_or_else(|p| p.into_inner());
        let view = current
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("receipt-policy view is unavailable"))?;
        anyhow::ensure!(
            view.account_key == self.cached_account_key
                && view.generation == self.current_generation()
                && view.required_ready,
            "receipt-policy view is stale or belongs to another account"
        );
        let actor = arkret_sdk::ActorId::account(
            self.active_authority()
                .ok_or_else(|| anyhow::anyhow!("receipt holder account is unavailable"))?,
        );
        anyhow::ensure!(
            view.view
                .complete_joined_members_for_scope(scope)?
                .is_some_and(|members| members.contains(&actor)),
            "receipt holder is not a current member of this exact scope"
        );
        view.view.read_receipt_policy(scope)
    }

    #[cfg(test)]
    pub(crate) fn install_read_receipt_current_for_test(
        &mut self,
        scope: arkret_sdk::ScopeRef,
        policy: Option<Value>,
    ) {
        if self.active_authority().is_none() {
            self.promote_accepted_context_for_test(&"did:web:alice.example".parse().unwrap());
        }
        let realm = scope.realm_id().clone();
        let actor = arkret_sdk::ActorId::account(self.active_authority().unwrap());
        let revision = arkret_wire::CurrentRevision {
            commit_id: arkret_wire::RealmCommitId::from_digest([44; 32]),
            stream_position: 1,
        };
        let selector = arkret_wire::CurrentSelector::ScopeReadReceiptPolicy {
            scope_ref: scope.clone(),
        };
        let mut guard = self.current_view.lock().unwrap();
        let mut entries = guard
            .as_ref()
            .filter(|view| view.view.realm_id == realm.as_str())
            .map(|view| view.view.entries.clone())
            .unwrap_or_default();
        entries.retain(|entry| !matches!(entry, arkret_wire::TypedCurrentRow::Value { selector: found, .. } if found == &selector));
        if let Some(value) = policy {
            entries.push(arkret_wire::TypedCurrentRow::Value {
                selector,
                source_stream_ref: arkret_wire::CommitStreamRef::from_scope(
                    &scope,
                    Some(realm.clone()),
                )
                .unwrap(),
                revision: revision.clone(),
                value,
            });
        }
        let parent_selector = arkret_wire::CurrentSelector::MemberState {
            actor_id: actor.clone(),
        };
        entries.retain(|entry| !matches!(entry, arkret_wire::TypedCurrentRow::Value { selector, .. } if selector == &parent_selector));
        entries.push(arkret_wire::TypedCurrentRow::Value {
            selector: parent_selector,
            source_stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            revision: revision.clone(),
            value: serde_json::json!({"membership":"join"}),
        });
        if let arkret_sdk::ScopeRef::Circle { circle_id, .. } = &scope {
            let member = arkret_wire::CurrentSelector::CircleMemberState {
                circle_id: circle_id.clone(),
                member_actor_id: actor,
            };
            entries.retain(|entry| !matches!(entry, arkret_wire::TypedCurrentRow::Value { selector, .. } if selector == &member));
            entries.push(arkret_wire::TypedCurrentRow::Value { selector: member, source_stream_ref: arkret_wire::CommitStreamRef::from_scope(&scope, Some(realm.clone())).unwrap(), revision: revision.clone(), value: serde_json::json!({"membership":"join","parent_membership_revision":revision,"effective_at":"2026-10-19T00:00:00.000Z"}) });
        }
        *guard = Some(super::CurrentProductView {
            account_key: self.cached_account_key.clone(),
            generation: self.current_generation(),
            required_ready: true,
            view: crate::current_projection::RealmCurrentView::new(realm.as_str(), entries, true)
                .unwrap(),
        });
    }

    /// Whether the installed view of `realm_id` carries every required value.
    pub(crate) fn current_product_view_ready(&self, realm_id: &str) -> bool {
        if self.cached_account_key.as_deref() != Some(self.effective_account_key().as_str()) {
            return false;
        }
        self.current_view
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|view| {
                view.account_key == self.cached_account_key
                    && view.view.realm_id == realm_id.trim()
                    && view.required_ready
            })
    }

    /// The typed current rows of `realm_id`, or `None` while no view of that
    /// Realm is installed. `None` is never an empty current set.
    pub(crate) fn realm_current_view_entries(
        &self,
        realm_id: &str,
    ) -> Option<Vec<arkret_wire::TypedCurrentRow>> {
        self.current_product_view()
            .and_then(|view| view.entries_for(realm_id).map(<[_]>::to_vec))
    }

    /// Return every canonical Realm id currently represented by the local
    /// collaboration projection. Callers use this to execute Realm-scoped
    /// protocol reads without inventing a cross-Realm wildcard.
    pub fn known_realm_ids(&self) -> Vec<arkret_sdk::RealmId> {
        let state = self.load();
        state
            .realm_tree_projections
            .keys()
            .chain(state.realm_collaboration_roles.keys())
            .filter_map(|realm_id| {
                arkret_sdk::RealmId::new(realm_id.clone())
                    .ok()
                    .map(|typed| (typed.to_string(), typed))
            })
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_values()
            .collect()
    }

    /// Has the Realm (security boundary, formerly Space)
    /// emitted a `ak.realm.destroy` event we've already received? The
    /// chat UI MUST gray out the send box and surface the
    /// "permanently retired" banner once this returns true.
    ///
    /// Backed by `realm_destroy_receipts`, which is updated as local raw
    /// operations are appended. This keeps the send-box guard at
    /// a constant-time lookup instead of scanning the raw operation log on
    /// every render.
    pub fn realm_is_destroyed(&self, realm_id: &str) -> bool {
        if realm_id.is_empty() {
            return false;
        }
        self.load()
            .realm_destroy_receipts
            .get(realm_id)
            .is_some_and(|state| state.destroyed)
    }

    pub fn save_realm_tree_projection(
        &mut self,
        projection_id: impl Into<String>,
        projection: Value,
    ) {
        self.ensure_cached_loaded();
        let projection_id = projection_id.into();
        if self.cached.realm_tree_projections.get(&projection_id) == Some(&projection) {
            return; // projection identical — skip flush + dirtying renders
        }
        self.cached
            .realm_tree_projections
            .insert(projection_id, projection);
        let _ = self.flush();
    }

    pub fn save_realm_collaboration_role(
        &mut self,
        realm_id: impl Into<String>,
        role: Option<arkret_sdk::CollaborationRealmRole>,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let changed = match role {
            Some(role) => {
                self.cached.realm_collaboration_roles.insert(realm_id, role) != Some(role)
            }
            None => self
                .cached
                .realm_collaboration_roles
                .remove(&realm_id)
                .is_some(),
        };
        if changed {
            let _ = self.flush();
        }
    }

    pub fn realm_collaboration_role(
        &self,
        realm_id: &str,
    ) -> Option<arkret_sdk::CollaborationRealmRole> {
        self.cached.realm_collaboration_roles.get(realm_id).copied()
    }

    pub(crate) fn realm_allows_spaces(&self, realm_id: &str) -> bool {
        if self.realm_collaboration_role(realm_id)
            == Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
        {
            return false;
        }
        !self
            .realm_current_state_entries(realm_id)
            .iter()
            .any(|entry| {
                let arkret_wire::TypedCurrentRow::Value {
                    selector, value, ..
                } = entry;
                *selector == arkret_wire::CurrentSelector::RealmGenesis
                    && serde_json::from_value::<arkret_sdk::RealmGenesis>(value.clone()).is_ok_and(
                        |genesis| genesis.purpose == arkret_sdk::RealmPurpose::DirectConversation,
                    )
            })
    }

    pub fn realm_state_snapshot_sync_status(
        &self,
        realm_id: &str,
    ) -> Option<RealmStateSnapshotSyncStatus> {
        self.load().realm_state_snapshot_sync.get(realm_id).cloned()
    }

    /// Drop every `realm_tree_projections` entry whose key isn't in `keep`.
    /// Used by the sync reconcile path when `after=None` so Realm/Space
    /// projection nodes the server no longer reports get pruned from the
    /// local cache instead of lingering as ghost entries in the sidebar.
    ///
    /// Also prunes the auxiliary per-Realm caches (`drafts`,
    /// `stream_cursors`, `read_cursors`, `realm_remarks`,
    /// `mls_local_checkpoints`, `move_submissions` keyed by Realm, the
    /// `read_receipt_*_overrides`,
    /// `realm_watch_levels`, and any leftover encrypted-message draft) so a
    /// pruned Realm/Space node doesn't leave private remnants behind.
    pub fn retain_realm_tree_projections<F>(&mut self, keep: F) -> Vec<String>
    where
        F: Fn(&str) -> bool,
    {
        self.ensure_cached_loaded();
        let removed: Vec<String> = self
            .cached
            .realm_tree_projections
            .keys()
            .filter(|id| !keep(id))
            .cloned()
            .collect();
        if removed.is_empty() {
            return removed;
        }
        for id in &removed {
            self.forget_realm_tree_projection_inner(id);
        }
        let _ = self.flush();
        removed
    }

    /// Remove a single Realm Tree projection node and every derived record
    /// keyed by the same id. Public entry point for `left_realms`-style sync
    /// deltas. Flushes once.
    pub fn forget_realm_tree_projection(&mut self, projection_id: &str) {
        self.ensure_cached_loaded();
        let trimmed = projection_id.trim();
        if trimmed.is_empty() {
            return;
        }
        self.forget_realm_tree_projection_inner(trimmed);
        let _ = self.flush();
    }

    fn forget_realm_tree_projection_inner(&mut self, projection_id: &str) {
        self.cached.realm_tree_projections.remove(projection_id);
        self.cached.realm_collaboration_roles.remove(projection_id);
        self.cached.realm_destroy_receipts.remove(projection_id);
        self.cached
            .stream_cursors
            .retain(|_, head| head.stream_ref.realm_id().as_str() != projection_id);
        self.cached.realm_authority_basis.remove(projection_id);
        self.cached.realm_remarks.remove(projection_id);
        self.cached.mls_local_checkpoints.remove(projection_id);
        self.cached.realm_watch_levels.remove(projection_id);
        self.cached
            .read_receipt_realm_overrides
            .remove(projection_id);
        self.cached
            .read_receipt_realm_display_overrides
            .remove(projection_id);
        // `read_cursors` are keyed by `"{realm}\n{kind}\n{ref}\n{track}"` —
        // strip every marker whose Realm prefix matches.
        let prefix = format!("{projection_id}\n");
        self.cached
            .read_cursors
            .retain(|key, _| !key.starts_with(&prefix));
        // `move_submissions` carry a `realm_id` field; drop matching entries.
        self.cached
            .move_submissions
            .retain(|_, record| record.realm_id != projection_id);
    }

    /// Whether the Realm-default scope of `realm_id` has an accepted MLS
    /// Genesis in the installed current view. This is positive evidence only:
    /// `false` also covers "not known yet", so gates that could leak plaintext
    /// must use [`crate::mls::send_gate`] instead.
    pub fn realm_projection_is_mls_encrypted(&self, realm_id: &str) -> bool {
        let Ok(realm) = arkret_sdk::RealmId::new(realm_id.to_owned()) else {
            return false;
        };
        matches!(
            self.installed_scope_mls_current(&arkret_sdk::ScopeRef::Realm { realm_id: realm }),
            crate::current_projection::ScopeMlsCurrent::Activated(_)
        )
    }

    /// Joined-actor hint from one complete installed verified current cut.
    /// A missing or incomplete cut is `None`. This is useful
    /// for conservative mismatch detection and reconciliation wakeups, but it
    /// never replaces verified membership Events or MLS governance proofs.
    pub fn complete_joined_member_hint_for_realm(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<std::collections::BTreeSet<arkret_sdk::ActorId>>> {
        let Some(view) = self.current_product_view() else {
            return Ok(None);
        };
        if view.realm_id != realm_id.trim() {
            return Ok(None);
        }
        view.complete_joined_members()
    }

    /// Detect the retired minimal-metadata marker in a locally cached Realm
    /// projection. A cached marker is not a profile activation fact: v1 has no
    /// such registered profile, and callers must fail closed instead of
    /// treating the Realm as ordinary or authoring under the old pairwise path.
    pub fn realm_projection_has_retired_minimal_metadata_marker(&self, realm_id: &str) -> bool {
        self.with_unoverlaid_account_fields(|state| {
            state
                .realm_tree_projections
                .get(realm_id)
                .is_some_and(realm_tree_projection_has_retired_minimal_metadata_marker)
        })
    }

    /// Transitional old callers still use this predicate; each authoring and
    /// receive path is being migrated to reject the marker explicitly.
    pub fn realm_projection_is_minimal_metadata(&self, realm_id: &str) -> bool {
        self.realm_projection_has_retired_minimal_metadata_marker(realm_id)
    }
}

/// Mark the installed view of `realm_id` as no longer covering the Realm's
/// required values until the next install. Takes the field so callers that
/// already hold a mutable borrow of another store field can use it.
pub(super) fn invalidate_current_view(
    view: &Mutex<Option<super::CurrentProductView>>,
    realm_id: &str,
) {
    if let Some(view) = view
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_mut()
        .filter(|view| view.view.realm_id == realm_id.trim())
    {
        view.required_ready = false;
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod read_receipt_tests {
    use super::*;

    #[test]
    fn read_receipt_send_rechecks_independent_scope_policy_target_and_membership() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = LocalStateStore::with_path(directory.path().join("receipt-send.json"));
        let realm: arkret_sdk::RealmId = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            .parse()
            .unwrap();
        let event = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [82; 32]);
        let strand: arkret_sdk::StrandId = "ak:strand:ASyFf0qTUQ55a2qZp5fuTXRnIgf3ovKChQZ_XSkxdIPK"
            .parse()
            .unwrap();
        let root = arkret_sdk::ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let circle = arkret_sdk::ScopeRef::Circle {
            realm_id: realm,
            circle_id: arkret_sdk::CircleId::from_event_id(&event),
        };
        store.install_read_receipt_current_for_test(
            root.clone(),
            Some(serde_json::json!({"disclosure":"disabled"})),
        );
        store.install_read_receipt_current_for_test(
            circle.clone(),
            Some(serde_json::json!({"disclosure":"required"})),
        );
        store.set_read_receipt_default_send(false);
        let mut state = serde_json::to_value(store.load()).unwrap();
        state["verified_message_commits"] = serde_json::json!([{
            "accepted_ref": {"event_id": event, "commit_id":arkret_sdk::RealmCommitId::from_digest([44;32]), "stream_ref":arkret_sdk::CommitStreamRef::from_scope(&circle, None).unwrap(), "stream_position":1},
            "actor_id":arkret_sdk::ActorId::account(store.active_authority().unwrap()), "scope_ref":circle, "strand_id":strand, "track_name":"discussion"
        }]);
        store.save(serde_json::from_value(state).unwrap());
        assert!(
            store
                .require_read_receipt_send(&circle, &strand, &event)
                .is_ok()
        );
        assert!(
            store
                .require_read_receipt_send(&root, &strand, &event)
                .is_err()
        );
        store.install_read_receipt_current_for_test(
            root,
            Some(serde_json::json!({"disclosure":"required"})),
        );
        store.install_read_receipt_current_for_test(
            circle.clone(),
            Some(serde_json::json!({"disclosure":"disabled"})),
        );
        assert!(
            store
                .require_read_receipt_send(&circle, &strand, &event)
                .is_err()
        );
        store.install_read_receipt_current_for_test(
            circle.clone(),
            Some(serde_json::json!({"visibility":"members"})),
        );
        assert!(
            store
                .require_read_receipt_send(&circle, &strand, &event)
                .is_err()
        );
        store.set_read_receipt_default_send(true);
        assert!(
            store
                .require_read_receipt_send(&circle, &strand, &event)
                .is_ok()
        );
        store.set_current_generation(1);
        assert!(
            store
                .require_read_receipt_send(&circle, &strand, &event)
                .is_err()
        );
    }

    #[test]
    fn read_receipt_render_policy_retracts_at_generation_change_reset_and_account_switch() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = LocalStateStore::with_path(directory.path().join("receipt-render.json"));
        store.promote_accepted_context_for_test(&"did:web:alice.example".parse().unwrap());
        let realm: arkret_sdk::RealmId = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            .parse()
            .unwrap();
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        store.install_read_receipt_current_for_test(scope.clone(), None);
        assert!(store.current_read_receipt_policy(&scope).is_ok());
        store.set_current_generation(1);
        assert!(store.current_read_receipt_policy(&scope).is_err());
        store
            .current_view
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .generation = 1;
        assert!(store.current_read_receipt_policy(&scope).is_ok());
        invalidate_current_view(&store.current_view, realm.as_str());
        assert!(store.current_read_receipt_policy(&scope).is_err());
        store
            .current_view
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .required_ready = true;
        store.set_current_reset_required(true);
        assert!(store.current_read_receipt_policy(&scope).is_err());
        store.promote_accepted_context_for_test(&"did:web:bob.example".parse().unwrap());
        assert!(store.current_read_receipt_policy(&scope).is_err());
    }
}
