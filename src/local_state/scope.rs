use super::*;

impl LocalStateStore {
    /// Read-only view of the root index. Mirrors [`Self::load`]: once the store
    /// has reconciled with persistence `self.root` is authoritative; before
    /// that a fresh store reads (and migrates) the index off the backing store
    /// so `&self` getters reflect the persisted state without a `&mut` load.
    fn effective_root(&self) -> RootIndex {
        if self.loaded.get() {
            self.root.clone()
        } else {
            self.load_persisted_root()
        }
    }

    /// The currently-active account DID (the foreground account whose entry
    /// `cached` mirrors), or `None` when signed out / before any account has
    /// been adopted on this browser.
    pub fn active_account_did(&self) -> Option<String> {
        self.effective_root().active_did
    }

    /// Every account DID with a persisted per-account entry on this browser.
    pub fn known_account_dids(&self) -> Vec<String> {
        self.effective_root().known_dids
    }

    /// Read a cross-account UI device preference (theme/locale/...), shared by
    /// every account on this browser. `None` when unset.
    pub fn device_pref(&self, key: &str) -> Option<String> {
        self.effective_root().device_prefs.values.get(key).cloned()
    }

    /// Set a cross-account UI device preference. Lives in the root index, not
    /// any account entry.
    pub fn set_device_pref(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.ensure_cached_loaded();
        self.root
            .device_prefs
            .values
            .insert(key.into(), value.into());
        let _ = self.flush();
    }

    /// Wipe every account-scoped projection field of the ACTIVE account while
    /// keeping that account's own device-level state (`local_identity`,
    /// `push_registration`, `telemetry_log`, `dpop_device_key`) and session
    /// grant. Called on a same-account server switch or soft cache reset —
    /// anything that means the cached *projection* is stale but the account
    /// itself is unchanged.
    ///
    /// With per-account isolation the preserved device fields belong to THIS
    /// account's own entry (no cross-account bleed), so keeping them is safe and
    /// keeps a re-sync on the same server/account cheap. Switching to a
    /// *different* account goes through [`Self::switch_active_account`], not
    /// this helper.
    ///
    /// The session grant is deliberately preserved here because the caller
    /// usually has its own opinion (a fresh-login strand has just written the
    /// grant; a logout strand follows up with explicit `set_session_grant(None)`).
    pub fn clear_account_scoped(&mut self) {
        self.ensure_cached_loaded();
        let preserved_identity = self.cached.local_identity.clone();
        let preserved_push = self.cached.push_registration.clone();
        let preserved_telemetry = std::mem::take(&mut self.cached.telemetry_log);
        let preserved_grant = self.cached.session_grant.clone();
        let preserved_dpop = self.cached.dpop_device_key.clone();
        // YOU-02-004: the MLS receive-chain overlay is account-scoped state —
        // wipe it so a stale decrypt write-back can't resurrect old snapshots.
        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
        self.cached = ClientLocalState {
            local_identity: preserved_identity,
            push_registration: preserved_push,
            telemetry_log: preserved_telemetry,
            session_grant: preserved_grant,
            dpop_device_key: preserved_dpop,
            ..ClientLocalState::default()
        };
        let _ = self.flush();
    }

    /// Make `actor` the active account, loading its own per-account entry.
    /// This is the per-account replacement for the old
    /// `stamp_account_scope_owner` / `adopt_account_scope` wipe dance: account
    /// isolation is now structural (one key per account), so switching is just
    /// re-pointing `root.active_did` and swapping `cached` for the target
    /// account's persisted entry — never wiping another account's data.
    ///
    /// Returns `true` when the active account actually changed.
    pub fn switch_active_account(&mut self, actor: &str) -> bool {
        self.ensure_cached_loaded();
        let actor = actor.trim();
        if actor.is_empty() {
            return false;
        }
        if self.root.active_did.as_deref() == Some(actor) {
            // Already active — just make sure it's recorded as known.
            self.root.note_known_did(actor);
            return false;
        }
        // Persist the outgoing account's entry before swapping so nothing is
        // lost (its own key, never another account's).
        let _ = self.flush();
        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
        self.root.active_did = Some(actor.to_owned());
        self.root.note_known_did(actor);
        // Load the target account's own entry (default for a brand-new account).
        self.cached = self.read_account_state(actor).unwrap_or_default();
        let _ = self.flush();
        true
    }

    /// Record `actor` as the active account without wiping anything. Used by
    /// paths that have validated the actor (e.g. the connect bootstrap's
    /// account-viewer probe) and just need the active pointer + known-DID set
    /// updated. When the active account is unchanged this is a cheap no-op.
    pub fn stamp_account_scope_owner(&mut self, actor: &str) {
        self.ensure_cached_loaded();
        let actor = actor.trim();
        if actor.is_empty() {
            return;
        }
        if self.root.active_did.as_deref() == Some(actor) {
            if !self.root.known_dids.iter().any(|known| known == actor) {
                self.root.note_known_did(actor);
                let _ = self.flush();
            }
            return;
        }
        self.switch_active_account(actor);
    }

    /// Adopt the account-scope for `actor`. With per-account isolation this is
    /// [`Self::switch_active_account`]: returning to a different account loads
    /// that account's own independent state (its grant, cursor, projections,
    /// device key), so a previous identity's revoked grant / foreign cursor can
    /// never leak — they live in a separate key entirely.
    ///
    /// Returns `true` when the active account changed.
    pub fn adopt_account_scope(&mut self, actor: &str) -> bool {
        self.switch_active_account(actor)
    }

    /// Purge a single account's persisted state: its `…account.<did>` entry,
    /// its secure-store wrap_seed namespace (wasm), and its `known_dids` entry.
    /// Cross-account [`DevicePrefs`] and every other account are untouched. When
    /// the purged account was active, the active pointer is cleared.
    pub fn forget_account(&mut self, actor: &str) {
        self.ensure_cached_loaded();
        let actor = actor.trim();
        if actor.is_empty() {
            return;
        }
        self.delete_account_state(actor);
        self.root.forget_known_did(actor);
        if self.root.active_did.as_deref() == Some(actor) {
            self.root.active_did = None;
            *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
            self.cached = ClientLocalState::default();
        }
        let _ = self.flush();
    }

    /// Pre-DID login kickoff: record the freshly-minted `device_id` (+ optional
    /// holder `jkt`) into the root index `pending_login` and pin the
    /// process-global pending namespace so the bootstrap wrap_seed / secrets
    /// land under `pending.<device_id>` until the principal DID resolves.
    pub fn begin_pending_login(&mut self, device_id: &str, dpop_jkt: Option<&str>) {
        self.ensure_cached_loaded();
        let device_id = device_id.trim();
        if device_id.is_empty() {
            return;
        }
        crate::secure_key_store::set_pending_login_device_id(Some(device_id));
        self.root.pending_login = Some(PendingLogin {
            device_id: device_id.to_owned(),
            dpop_jkt: dpop_jkt
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        });
        let _ = self.flush();
    }

    /// The in-flight pre-DID login material, if any.
    pub fn pending_login(&self) -> Option<PendingLogin> {
        self.root.pending_login.clone()
    }

    /// Adopt the pending pre-DID device material onto the resolved principal
    /// `did` (session grant has returned the DID). Two outcomes:
    ///
    /// * `did` already has a persisted entry (a returning account on this
    ///   browser) → DISCARD the pending device material; the returning account
    ///   keeps its own stable `device_id` + key (`cnf.jkt` stays stable).
    ///   Returns `false` (not a new account).
    /// * `did` is new on this browser → keep the pending device material as the
    ///   new account's device. Returns `true` (new account).
    ///
    /// Either way the pending entry is cleared and `did` becomes active. The
    /// secure-store device seed re-homing itself is handled by
    /// `adopt_device_seed_scope_on_login`; this drives the root-index side and
    /// the active-account switch.
    pub fn adopt_pending_login(&mut self, did: &str) -> bool {
        self.ensure_cached_loaded();
        let did = did.trim();
        if did.is_empty() {
            return false;
        }
        let is_returning_account = self.root.known_dids.iter().any(|known| known == did)
            || self.read_account_state(did).is_some();
        // Clear pending namespace pin before the seed-scope adopt re-homes it.
        crate::secure_key_store::set_pending_login_device_id(None);
        self.root.pending_login = None;
        self.switch_active_account(did);
        !is_returning_account
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
            let _ = secure_store.delete_secret(
                &crate::secure_key_store::account_scoped_device_key(Self::SECURE_DPOP_DEVICE_KEY),
            );
        }
        self.ensure_cached_loaded();
        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
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
            if let Err(error) = secure_store.delete_secret(
                &crate::secure_key_store::account_scoped_device_key(Self::SECURE_DPOP_DEVICE_KEY),
            ) {
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
                secure_store.delete_secret(
                    &crate::secure_key_store::account_scoped_device_key(
                        Self::SECURE_DPOP_DEVICE_KEY,
                    ),
                )?;
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
