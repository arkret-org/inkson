use super::*;

impl LocalStateStore {
    /// Wipe every account-scoped projection field while keeping
    /// device-level state (`local_identity`, `push_registration`,
    /// `telemetry_log`) and the auth-token state (`oidc_tokens`,
    /// `session_grant`). Called on logout, when the principal DID
    /// changes between logins, or when the user switches servers —
    /// anything that means the cached *projection* no longer
    /// represents the current viewer.
    ///
    /// The auth tokens are deliberately preserved here because the
    /// caller usually has its own opinion: a fresh-login strand has just
    /// written the new account's tokens via `set_oidc_tokens` and would
    /// be sad to see them disappear, while a `logout` strand follows up
    /// with explicit `set_oidc_tokens(None)` + `set_session_grant(None)`
    /// of its own. Bundling the token clear into this helper would have
    /// made the account-change-during-connect path racy.
    ///
    /// Pairs with [`Self::retain_realm_tree_projections`] which only handles
    /// the steady-state sync reconcile case.
    pub fn clear_account_scoped(&mut self) {
        self.ensure_cached_loaded();
        let preserved_identity = self.cached.local_identity.clone();
        let preserved_push = self.cached.push_registration.clone();
        let preserved_telemetry = std::mem::take(&mut self.cached.telemetry_log);
        let preserved_oidc = self.cached.oidc_tokens.clone();
        let preserved_grant = self.cached.session_grant.clone();
        // G3.Y0 — the DPoP device key is device-level state, same
        // semantics as `local_identity`. Preserved across the
        // soft-logout / account-change paths so a re-authentication on
        // this device keeps `cnf.jkt` stable; only the hard-logout strand
        // (`clear_device_scoped`) wipes it.
        let preserved_dpop = self.cached.dpop_device_key.clone();
        // YOU-02-004: the MLS receive-chain overlay is account-scoped state —
        // wipe it with the rest so a stale decrypt write-back can't resurrect
        // the previous account's MLS snapshots through a later flush merge.
        *self.mls_receive_overlay.lock().unwrap() = MlsReceiveOverlay::default();
        self.cached = ClientLocalState {
            local_identity: preserved_identity,
            push_registration: preserved_push,
            telemetry_log: preserved_telemetry,
            oidc_tokens: preserved_oidc,
            session_grant: preserved_grant,
            dpop_device_key: preserved_dpop,
            ..ClientLocalState::default()
        };
        let _ = self.flush();
    }

    /// Stamp the current account-scope owner without wiping anything.
    /// Used by paths that have already validated the actor (e.g. the
    /// connect bootstrap's account viewer probe) and just need to record
    /// who the account-scoped state now belongs to so a later
    /// [`adopt_account_scope`](Self::adopt_account_scope) recognises it.
    pub fn stamp_account_scope_owner(&mut self, actor: &str) {
        self.ensure_cached_loaded();
        let actor = actor.trim();
        let next = (!actor.is_empty()).then(|| actor.to_owned());
        if self.cached.account_scope_owner == next {
            return;
        }
        self.cached.account_scope_owner = next;
        let _ = self.flush();
    }

    /// Adopt the account-scope for `actor`. When the persisted scope
    /// belongs to a *different* — or unknown — actor, every account-scoped
    /// record is wiped first: sync cursor, projections, drafts, **and the
    /// session grant + OIDC bundle** (which `clear_account_scoped` alone
    /// preserves — wrong across an identity change). Device-level state
    /// (local identity, push registration, DPoP key) is preserved.
    ///
    /// This is the single guard that stops a previous identity's *revoked*
    /// session grant or *foreign-principal* sync cursor from bleeding into
    /// a freshly established session — the root of the `cursor_integrity_invalid`
    /// / `session grant is not active: revoked` cascade. Call it whenever a
    /// session is (re-)established for `actor` (login, and the connect
    /// bootstrap once the canonical actor is known).
    ///
    /// Returns `true` when a wipe happened.
    pub fn adopt_account_scope(&mut self, actor: &str) -> bool {
        self.ensure_cached_loaded();
        let actor = actor.trim();
        let owner_matches = self
            .cached
            .account_scope_owner
            .as_deref()
            .map(str::trim)
            .is_some_and(|owner| !owner.is_empty() && owner == actor);
        if owner_matches {
            return false;
        }
        self.clear_account_scoped();
        self.cached.session_grant = None;
        self.cached.oidc_tokens = None;
        self.cached.account_scope_owner = (!actor.is_empty()).then(|| actor.to_owned());
        let _ = self.flush();
        true
    }

    /// G3.Y0 — hard logout: wipe everything `clear_account_scoped`
    /// would wipe, PLUS the device DPoP key, push registration, and
    /// local identity. The next sign-in starts from a clean slate
    /// (new `cnf.jkt`, new `did:key`).
    ///
    /// Distinct from `clear_account_scoped` (which is the soft path —
    /// session expired, server-switch, account-change). The split is
    /// the public surface for the G3.Y0 soft-vs-hard logout contract:
    /// soft keeps device material so the user can re-authenticate on
    /// the same `cnf.jkt`; hard rotates the device key.
    pub fn clear_device_scoped(&mut self) {
        #[cfg(not(test))]
        {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            let _ = secure_store.delete_secret(Self::SECURE_DPOP_DEVICE_KEY);
        }
        self.ensure_cached_loaded();
        *self.mls_receive_overlay.lock().unwrap() = MlsReceiveOverlay::default();
        self.cached = ClientLocalState::default();
        let _ = self.flush();
    }

    /// G3.Y0 — read the persisted device DPoP key, if any.
    pub fn dpop_device_key(&self) -> Option<DpopDeviceKeyRecord> {
        self.load().dpop_device_key
    }

    /// G3.Y0 — persist (or clear via `None`) the device DPoP key.
    pub fn set_dpop_device_key(&mut self, record: Option<DpopDeviceKeyRecord>) {
        #[cfg(not(test))]
        if record.is_none() {
            let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
            if let Err(error) = secure_store.delete_secret(Self::SECURE_DPOP_DEVICE_KEY) {
                tracing::debug!(
                    ?error,
                    "secure_key_store DPoP key delete on clear failed (likely already missing)",
                );
            }
        }
        self.ensure_cached_loaded();
        self.cached.dpop_device_key = record;
        let _ = self.flush();
    }

    /// Persist the DPoP key through `SecureKeyStore`. The private seed
    /// is written to the secure backend; `state.json` keeps only the
    /// public diagnostics (`jkt`, `created_at`) with an empty seed.
    pub fn set_dpop_device_key_with_secure_store(
        &mut self,
        record: Option<DpopDeviceKeyRecord>,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> Result<Option<DpopDeviceKeyRecord>, crate::secure_key_store::SecureKeyStoreError> {
        let public_record = match record {
            Some(record) => {
                store_dpop_device_key_in_secure_store(secure_store, &record)?;
                let mut public_record = record;
                public_record.seed_b64.clear();
                Some(public_record)
            }
            None => {
                secure_store.delete_secret(Self::SECURE_DPOP_DEVICE_KEY)?;
                None
            }
        };
        self.ensure_cached_loaded();
        self.cached.dpop_device_key = public_record.clone();
        let _ = self.flush();
        Ok(public_record)
    }

    /// Load the DPoP key from `SecureKeyStore`.
    pub fn load_dpop_device_key_with_secure_store(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> Result<Option<DpopDeviceKeyRecord>, crate::secure_key_store::SecureKeyStoreError> {
        load_dpop_device_key_from_secure_store(secure_store)
    }

    pub fn migrate_local_only_drafts_to_account_data(
        &mut self,
        namespace_key: &[u8],
        origin_device_id: &str,
        updated_hlc: &str,
        retention_expires_at: &str,
    ) -> anyhow::Result<Vec<crate::account_data::DraftAccountDataItem>> {
        self.ensure_cached_loaded();
        let migrated = crate::account_data::migrate_legacy_local_drafts(
            namespace_key,
            &self.cached.drafts,
            origin_device_id,
            updated_hlc,
            retention_expires_at,
        )?;
        for item in &migrated {
            self.cached.draft_account_data.insert(
                item.account_data_key.clone(),
                serde_json::to_value(&item.value)?,
            );
        }
        if !migrated.is_empty() {
            let _ = self.flush();
        }
        Ok(migrated)
    }

    pub fn migrate_local_only_saved_items_to_account_data(
        &mut self,
        namespace_key: &[u8],
        items: &[crate::account_data::LegacySavedItem],
        updated_hlc: &str,
    ) -> anyhow::Result<Vec<crate::account_data::SavedAccountDataItem>> {
        self.ensure_cached_loaded();
        let migrated =
            crate::account_data::migrate_legacy_saved_items(namespace_key, items, updated_hlc)?;
        for item in &migrated {
            self.cached.saved_account_data.insert(
                item.account_data_key.clone(),
                crate::account_data::saved_item_account_data_value(&item.value)?,
            );
        }
        if !migrated.is_empty() {
            let _ = self.flush();
        }
        Ok(migrated)
    }

    pub fn stage_saved_account_data_item(
        &mut self,
        item: &crate::account_data::SavedAccountDataItem,
    ) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        self.cached.saved_account_data.insert(
            item.account_data_key.clone(),
            crate::account_data::saved_item_account_data_value(&item.value)?,
        );
        let _ = self.flush();
        Ok(())
    }

    pub fn stage_saved_account_data_entry(
        &mut self,
        account_data_key: impl Into<String>,
        value: Value,
    ) {
        self.ensure_cached_loaded();
        self.cached
            .saved_account_data
            .insert(account_data_key.into(), value);
        let _ = self.flush();
    }

    pub fn remove_saved_account_data_entry(&mut self, account_data_key: &str) {
        self.ensure_cached_loaded();
        if self
            .cached
            .saved_account_data
            .remove(account_data_key)
            .is_some()
        {
            let _ = self.flush();
        }
    }

    pub fn draft_account_data_entries(&self) -> BTreeMap<String, Value> {
        self.load().draft_account_data
    }

    pub fn saved_account_data_entries(&self) -> BTreeMap<String, Value> {
        self.load().saved_account_data
    }

    pub fn save_draft(&mut self, draft_scope_id: impl Into<String>, draft: impl Into<String>) {
        self.ensure_cached_loaded();
        let draft_scope_id = draft_scope_id.into();
        let draft = draft.into();
        if draft.trim().is_empty() {
            if self.cached.drafts.remove(&draft_scope_id).is_none() {
                return; // nothing to clear — skip flush
            }
        } else {
            if self.cached.drafts.get(&draft_scope_id) == Some(&draft) {
                return; // draft unchanged — skip flush
            }
            self.cached.drafts.insert(draft_scope_id, draft);
        }
        let _ = self.flush();
    }

    pub fn draft_for(&self, draft_scope_id: &str) -> String {
        self.cached
            .drafts
            .get(draft_scope_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn preserve_encrypted_message(
        &mut self,
        message_id: impl Into<String>,
        payload: EncryptedPayload,
    ) {
        self.ensure_cached_loaded();
        self.cached
            .pending_encrypted_messages
            .insert(message_id.into(), payload);
        let _ = self.flush();
    }

    pub fn pending_encrypted_count(&self) -> usize {
        self.cached.pending_encrypted_messages.len()
    }
}
