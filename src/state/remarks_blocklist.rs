use super::*;

fn verified_bundle_covers_observed_head(
    bundle: &arkret_sdk::MlsGovernanceProofBundle,
    accepted_heads: &BTreeSet<&str>,
) -> bool {
    bundle
        .proof_material
        .seal_descriptors
        .iter()
        .any(|descriptor| accepted_heads.contains(descriptor.seal_ref.as_str()))
}

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
        self.cached.accepted_human_contact_principals = contacts
            .iter()
            .filter(|contact| contact.state == arkret_sdk::ContactState::Accepted)
            .filter_map(|contact| match &contact.peer {
                arkret_sdk::contact_operations::ContactPeer::Human { account_id } => {
                    Some(account_id.principal_id.to_string())
                }
                arkret_sdk::contact_operations::ContactPeer::Agent { .. } => None,
            })
            .collect();
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
            let _ = self.flush();
        }
        changed
    }

    /// Append a typed block (`kind` ∈ actor / service / domain / organization)
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
            if let Some(actor) = actor {
                self.cached
                    .pending_personal_block_sagas
                    .insert(actor.to_string());
            }
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
        let _ = self.flush();
    }

    pub fn pending_personal_block_sagas(&self) -> BTreeSet<String> {
        self.load().pending_personal_block_sagas
    }

    pub fn complete_personal_block_saga(&mut self, peer_id: &str) {
        self.ensure_cached_loaded();
        if self.cached.pending_personal_block_sagas.remove(peer_id) {
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

    /// Get the latest Seal view for a Realm. Returns the Default view
    /// (empty frontier / empty leaves / no state_root) when none has been
    /// observed yet — Move builders treat that as "use sha256(empty)
    /// sentinel".
    pub fn seal_view_for_realm(&self, realm_id: &str) -> LocalSealView {
        self.load()
            .seal_views
            .get(realm_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Replace the Seal view snapshot for a Realm. Called from the sync
    /// path once the `/sync` response surfaces the projection's Seal
    /// view. Tests use this to seed Move-frontier behavior.
    pub fn set_realm_seal_view(&mut self, realm_id: impl Into<String>, view: LocalSealView) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        if self.cached.seal_views.get(&realm_id) == Some(&view) {
            return; // seal view unchanged — skip flush
        }
        let accepted_heads = view
            .frontier
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        self.cached.mls_governance_proofs.retain(|_, entry| {
            entry.request.effective_scope.realm_id_opt().map(|id| id.as_str())
                != Some(realm_id.as_str())
                || entry
                    .proof_target_basis
                    .leaves
                    .iter()
                    .all(|seal| accepted_heads.contains(seal.as_str()))
                // Sync and proof acquisition race independently. A lagging
                // frontier may still be an authenticated predecessor of the
                // freshly verified accepted Seal and must not evict its proof.
                || verified_bundle_covers_observed_head(&entry.bundle, &accepted_heads)
        });
        self.cached.seal_views.insert(realm_id, view);
        let _ = self.flush();
    }

    /// Fold a per-Realm `/sync` body into the stored Seal view.
    ///
    /// This is the ONLY entry point the sync path may use. `client-sync.md`
    /// defines no Seal view on the Realm delta, so a body without `seal_view`
    /// says nothing about the frontier; replacing the stored view with the
    /// resulting empty one would drop the authoritative frontier obtained from
    /// `ak.self.seals.read.frontier.v1` and make [`Self::set_realm_seal_view`]
    /// evict every verified MLS governance proof for the Realm. See
    /// [`LocalSealView::merged_from_sync_body`].
    pub fn merge_realm_seal_view_from_sync_body(&mut self, realm_id: &str, body: &Value) {
        let merged = self
            .seal_view_for_realm(realm_id)
            .merged_from_sync_body(body);
        self.set_realm_seal_view(realm_id.to_owned(), merged);
    }

    /// All known Seal views — handy for app-wide UI banners.
    pub fn seal_views(&self) -> BTreeMap<String, LocalSealView> {
        self.load().seal_views
    }

    /// Convenience: pick the right `seal_ref` to thread into a Move
    /// builder for a given Realm. Returns the lex-min frontier head when
    /// available, otherwise the `sha256(empty)` sentinel. Mirrors
    /// [`LocalSealView::move_seal_ref`].
    pub fn seal_ref_for_realm_move(&self, realm_id: &str) -> String {
        self.seal_view_for_realm(realm_id).move_seal_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::verified_bundle_covers_observed_head;

    #[test]
    fn verified_bundle_recognizes_an_observed_predecessor_head() {
        let bundle = arkret_sdk::MlsGovernanceProofBundle {
            query_digest: arkret_sdk::Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
            frontier_projection: arkret_sdk::MlsGovernanceFrontierProjection {
                frontier_registry_digest: arkret_sdk::Hash::new(format!(
                    "sha256:{}",
                    "11".repeat(32)
                ))
                .unwrap(),
                branches: Vec::new(),
            },
            proof_material: arkret_sdk::MlsGovernanceTypedProofMaterial {
                seal_descriptors: vec![arkret_sdk::MlsGovernanceSealDescriptor {
                    seal_ref: arkret_sdk::SealId::new(
                        "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    )
                    .unwrap(),
                }],
                seal_predecessor_edges: Vec::new(),
                event_ids: Vec::new(),
            },
            page_digest: arkret_sdk::Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap(),
        };
        let previous = BTreeSet::from([
            "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ]);
        let unrelated = BTreeSet::from(["ak:seal:sha256:unrelated"]);

        assert!(verified_bundle_covers_observed_head(&bundle, &previous));
        assert!(!verified_bundle_covers_observed_head(&bundle, &unrelated));
    }
}
