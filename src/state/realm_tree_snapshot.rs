use super::*;

impl LocalStateStore {
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

    /// Round R2/R3 (T07) — has the Realm (security boundary, formerly Space)
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
        self.load().realm_collaboration_roles.get(realm_id).copied()
    }

    pub fn apply_snapshot_chunks(
        &mut self,
        manifest: &arkret_sdk::SnapshotManifest,
        chunks: &[arkret_sdk::SnapshotChunkPayload],
        trust_state: crate::snapshot::SnapshotTrustState,
    ) -> anyhow::Result<()> {
        let report = arkret_sdk::verify_snapshot_manifest(
            manifest,
            chunks,
            &arkret_sdk::SnapshotVerifyOptions::standard(
                Utc::now(),
                arkret_sdk::CORE_REDUCER_PROFILE,
            ),
        )
        .map_err(|error| anyhow::anyhow!("{}: {}", error.code.as_str(), error.message))?;

        let mut projections = Vec::new();
        let mut encrypted_messages = Vec::new();
        for chunk in chunks {
            for item in &chunk.items {
                if item.id.trim().is_empty() {
                    anyhow::bail!("snapshot item id must not be empty");
                }
                projections.push((item.id.clone(), item.object.clone()));
                if let Some(payload) = snapshot_item_encrypted_payload(item) {
                    encrypted_messages.push((item.id.clone(), payload));
                }
            }
        }

        let status = SnapshotSyncStatus {
            manifest_id: manifest.id.to_string(),
            trust_state,
            updated_at: Utc::now(),
            source_event_ids: report
                .source_event_ids
                .into_iter()
                .map(|event_id| event_id.to_string())
                .collect(),
            degraded_reason: None,
        };
        let realm_id = manifest.realm_id.to_string();

        self.batch(|store| {
            for (projection_id, projection) in projections {
                store.save_realm_tree_projection(projection_id, projection);
            }
            for (message_id, payload) in encrypted_messages {
                store.preserve_encrypted_message(message_id, payload);
            }
            store.ensure_cached_loaded();
            store.cached.snapshot_sync.insert(realm_id, status);
            store.flush_pending.store(true, Ordering::Relaxed);
        });
        Ok(())
    }

    pub fn snapshot_sync_status(&self, realm_id: &str) -> Option<SnapshotSyncStatus> {
        self.load().snapshot_sync.get(realm_id).cloned()
    }

    /// Drop every `realm_tree_projections` entry whose key isn't in `keep`.
    /// Used by the sync reconcile path when `after=None` so Realm/Space
    /// projection nodes the server no longer reports get pruned from the
    /// local cache instead of lingering as ghost entries in the sidebar.
    ///
    /// Also prunes the auxiliary per-Realm caches (`drafts`,
    /// `seal_views`, `read_cursors`, `realm_remarks`,
    /// `mls_snapshots`, `move_submissions` keyed by Realm, the
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
        self.cached.seal_views.remove(projection_id);
        self.cached.realm_remarks.remove(projection_id);
        self.cached.mls_snapshots.remove(projection_id);
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
        // `pending_encrypted_messages` are keyed by message id, not space id,
        // so we leave them alone — the per-message flush path will reject
        // them if the target Space is gone.
    }

    /// True when the latest cached realm-tree projection declares an
    /// MLS-backed encryption profile. Used by membership/admin surfaces
    /// to decide whether a membership frontier change must pause sends
    /// until an MLS commit covers it.
    pub fn realm_projection_is_mls_encrypted(&self, realm_id: &str) -> bool {
        self.load()
            .realm_tree_projections
            .get(realm_id)
            .is_some_and(crate::security_state::realm_projection_is_encrypted)
    }

    /// Joined-principal projection hint when account sync explicitly says the
    /// roster is complete. A missing/limited roster is `None`. This is useful
    /// for conservative mismatch detection and reconciliation wakeups, but it
    /// never replaces verified membership Events or MLS governance proofs.
    pub fn complete_joined_member_hint_for_realm(
        &self,
        realm_id: &str,
    ) -> Option<std::collections::BTreeSet<String>> {
        let state = self.load();
        let projection = state.realm_tree_projections.get(realm_id.trim())?;
        if projection.get("members_limited").and_then(Value::as_bool) != Some(false) {
            return None;
        }
        let members = projection.get("members").and_then(Value::as_array)?;
        Some(
            members
                .iter()
                .filter(|member| member.get("membership").and_then(Value::as_str) == Some("join"))
                .filter_map(|member| {
                    member
                        .get("actor_id")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|actor_id| !actor_id.is_empty())
                        .map(ToOwned::to_owned)
                })
                .collect(),
        )
    }

    /// The effective `durability_policy` (RRK, realm-and-space.md §2.3.1) for
    /// `realm_id` from the latest cached realm-tree projection, if declared.
    /// SDK-typed so the client and the reducer share one closed union. `None`
    /// when no projection declares a registered value.
    pub fn realm_durability_policy(&self, realm_id: &str) -> Option<arkret_wire::DurabilityPolicy> {
        self.load()
            .realm_tree_projections
            .get(realm_id.trim())
            .and_then(super::realm_tree_projection_value_durability_policy)
    }

    /// The effective `content_scheme` selector for `realm_id`. RRK durability is
    /// only effective when this is `mls_exporter_aead_v1`
    /// (encryption-and-audit.md §2.10.8). `None` means the authoritative
    /// security projection is incomplete; encrypted sends must remain paused
    /// instead of guessing the `mls_rfc9420` wire scheme.
    pub fn realm_content_scheme(&self, realm_id: &str) -> Option<String> {
        self.load()
            .realm_tree_projections
            .get(realm_id.trim())
            .and_then(crate::realm_tree::realm_projection_content_scheme)
    }

    /// The create-locked content scheme for one independent Circle MLS group.
    pub fn circle_content_scheme(&self, realm_id: &str, circle_id: &str) -> Option<String> {
        self.load()
            .realm_tree_projections
            .get(realm_id.trim())
            .and_then(|body| {
                crate::realm_tree::circle_projection_content_scheme(body, circle_id.trim())
            })
    }

    /// The create-locked durability selector for one independent Circle MLS
    /// group, resolved from the accepted Circle create projection.
    pub fn circle_durability_policy(
        &self,
        realm_id: &str,
        circle_id: &str,
    ) -> Option<arkret_sdk::DurabilityPolicy> {
        self.load()
            .realm_tree_projections
            .get(realm_id.trim())
            .and_then(|body| {
                crate::realm_tree::circle_projection_durability_policy(body, circle_id.trim())
            })
    }

    /// The effective `history_access` from the current projected facet
    /// state, with materialized/create snapshots used only as fallbacks.
    pub fn realm_history_access(&self, realm_id: &str) -> Option<String> {
        self.load()
            .realm_tree_projections
            .get(realm_id.trim())
            .and_then(crate::realm_tree::realm_projection_history_access)
    }
    /// SEC-08 (`encryption-and-audit.md` §2.9) — does the latest cached
    /// realm-tree projection declare the
    /// `ak.profile.mls.minimal_metadata_realm.v1` profile? The committer uses
    /// this to decide whether the ≤1h epoch-lifetime cap applies to a given
    /// Realm. Unknown / absent projection ⇒ `false` (the realm is treated as a
    /// normal realm).
    pub fn realm_projection_is_minimal_metadata(&self, realm_id: &str) -> bool {
        self.load()
            .realm_tree_projections
            .get(realm_id)
            .is_some_and(realm_tree_projection_value_is_minimal_metadata)
    }
}
