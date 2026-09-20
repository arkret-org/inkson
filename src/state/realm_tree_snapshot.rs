use super::*;

impl LocalStateStore {
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

    pub(crate) fn product_current_strands(
        &self,
        authority: &arkret_sdk::AccountId,
        realm: &str,
    ) -> Option<Vec<arkret_sdk::StrandId>> {
        self.product_current_demand
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .filter(|(a, r, ..)| a == authority && r == realm)
            .map(|(_, _, strands, _)| strands.clone())
    }

    /// Extra typed current selectors the active product view is demanding on
    /// top of the Realm-required ones. Each is a domain coordinate the Station
    /// answers with its own `CurrentRevision`; there is no Realm-global
    /// revision to demand.
    pub(crate) fn product_current_selectors(
        &self,
        authority: &arkret_sdk::AccountId,
        realm: &str,
    ) -> Vec<arkret_wire::CurrentSelector> {
        self.product_current_demand
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .filter(|(a, r, ..)| a == authority && r == realm)
            .map(|(_, _, _, selectors)| selectors.clone())
            .unwrap_or_default()
    }

    pub(crate) fn realm_tree_projection(&self, realm_id: &str) -> Option<Value> {
        self.cached.realm_tree_projections.get(realm_id).cloned()
    }

    pub(crate) fn install_current_product_view(
        &mut self,
        realm_id: &str,
        entries: Vec<arkret_wire::TypedCurrentResult>,
        ready: bool,
    ) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        // Keep only the active Realm's bounded current view in the account
        // blob. Full rows and baseline seen markers belong to CurrentIndex.
        for (id, projection) in &mut self.cached.realm_tree_projections {
            if id != realm_id {
                if let Some(object) = projection.as_object_mut() {
                    object.remove("current");
                    object.remove("__current_required_ready");
                }
            }
        }
        let projection = self
            .cached
            .realm_tree_projections
            .entry(realm_id.to_owned())
            .or_insert_with(|| serde_json::json!({}));
        crate::current_projection::install_bounded_view(projection, realm_id, entries)?;
        projection["__current_required_ready"] = Value::Bool(ready);
        self.flush()
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
        mut projection: Value,
    ) {
        self.ensure_cached_loaded();
        let projection_id = projection_id.into();
        // Realm creation no longer locks an encryption mechanism. These old
        // projection carriers must not survive in the durable account blob or
        // be used as a pre-Genesis default after reload: accepted
        // `ak.mls.genesis` current is the only activation fact. Strip the
        // historical root/summary/facet spellings while retaining unrelated
        // Realm presentation data.
        fn strip_removed_encryption_carriers(value: &mut Value) {
            let Some(object) = value.as_object_mut() else {
                return;
            };
            for key in [
                "content_scheme",
                "encryption_profile",
                "encryption_floor",
                "durability_policy",
            ] {
                object.remove(key);
            }
            for container in ["summary", "object", "realm", "metadata", "history_facet"] {
                if let Some(nested) = object.get_mut(container) {
                    strip_removed_encryption_carriers(nested);
                }
            }
        }
        strip_removed_encryption_carriers(&mut projection);
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
    /// `read_receipt_*_overrides`, `read_receipt_policy_snapshots`,
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
        self.cached
            .read_receipt_policy_snapshots
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

    /// True when the Realm's own default scope has an accepted
    /// `ak.mls.genesis` in the cached typed current results.
    ///
    /// This is the single client-side judgement of "is this scope encrypted":
    /// a scope is plaintext until its own genesis commits and is irreversibly
    /// standard RFC 9420 afterwards. There is no create-locked encryption
    /// profile or encryption floor to read.
    pub fn realm_projection_is_mls_encrypted(&self, realm_id: &str) -> bool {
        let Ok(realm) = arkret_sdk::RealmId::new(realm_id.to_owned()) else {
            return false;
        };
        let entries = self.cached_current_entries(realm_id);
        crate::current_projection::scope_has_accepted_mls_genesis(
            &entries,
            &arkret_sdk::ScopeRef::Realm { realm_id: realm },
        )
    }

    /// Typed current results last installed for `realm_id` by
    /// [`Self::install_current_product_view`].
    pub(crate) fn cached_current_entries(
        &self,
        realm_id: &str,
    ) -> Vec<arkret_wire::TypedCurrentResult> {
        self.load()
            .realm_tree_projections
            .get(realm_id)
            .and_then(|projection| projection.get("current"))
            .and_then(|current| {
                serde_json::from_value::<Vec<arkret_wire::TypedCurrentResult>>(current.clone()).ok()
            })
            .unwrap_or_default()
    }

    /// Joined-actor projection hint when account sync explicitly says the
    /// roster is complete. A missing/limited roster is `None`. This is useful
    /// for conservative mismatch detection and reconciliation wakeups, but it
    /// never replaces verified membership Events or MLS governance proofs.
    pub fn complete_joined_member_hint_for_realm(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<std::collections::BTreeSet<arkret_sdk::ActorId>>> {
        let state = self.load();
        let Some(projection) = state.realm_tree_projections.get(realm_id.trim()) else {
            return Ok(None);
        };
        if projection
            .get("member_roster_entries_limited")
            .and_then(Value::as_bool)
            != Some(false)
        {
            return Ok(None);
        }
        let members = projection
            .get("member_roster_entries")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("complete Realm roster omits member entries"))?;
        Ok(Some(
            members
                .iter()
                .filter(|member| member.get("membership").and_then(Value::as_str) == Some("join"))
                .map(|member| {
                    serde_json::from_value::<arkret_sdk::ActorId>(
                        member.get("actor_id").cloned().unwrap_or(Value::Null),
                    )
                })
                .collect::<Result<_, _>>()?,
        ))
    }

    /// Detect the retired minimal-metadata marker in a locally cached Realm
    /// projection. A cached marker is not a profile activation fact: v1 has no
    /// such registered profile, and callers must fail closed instead of
    /// treating the Realm as ordinary or authoring under the old pairwise path.
    pub fn realm_projection_has_retired_minimal_metadata_marker(&self, realm_id: &str) -> bool {
        self.load()
            .realm_tree_projections
            .get(realm_id)
            .is_some_and(realm_tree_projection_has_retired_minimal_metadata_marker)
    }

    /// Transitional old callers still use this predicate; each authoring and
    /// receive path is being migrated to reject the marker explicitly.
    pub fn realm_projection_is_minimal_metadata(&self, realm_id: &str) -> bool {
        self.realm_projection_has_retired_minimal_metadata_marker(realm_id)
    }
}
