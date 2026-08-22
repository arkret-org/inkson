use super::*;

impl LocalStateStore {
    /// The authenticated foreground principal core id.
    pub fn active_principal_id(&self) -> Option<String> {
        let root = self.read_root();
        root.pending_login
            .is_none()
            .then(|| {
                root.active_entry()
                    .map(|entry| entry.authority.principal_id.to_string())
            })
            .flatten()
    }

    pub fn active_authority(&self) -> Option<arkret_sdk::PrincipalAuthorityKey> {
        let root = self.read_root();
        root.pending_login
            .is_none()
            .then(|| root.active_entry().map(|entry| entry.authority.clone()))
            .flatten()
    }

    /// Last profile selected on this installation. This survives sign-in
    /// failure/cancellation and is never used as authority for the pending
    /// transaction.
    pub fn last_selected_principal_id(&self) -> Option<String> {
        self.read_root()
            .active_entry()
            .map(|entry| entry.authority.principal_id.to_string())
    }

    /// Whether `principal` is the foreground identity. Equality is based on
    /// the stable DID core id, so a legitimate full-id resolution update does
    /// not create a second local account namespace.
    pub fn active_account_matches(&self, principal: &arkret_sdk::DidCoreId) -> bool {
        self.active_authority()
            .is_some_and(|authority| authority.principal_id == *principal)
    }

    /// Every account DID with a persisted per-account entry on this browser.
    pub fn known_principal_ids(&self) -> Vec<String> {
        self.read_root()
            .known_profiles
            .into_iter()
            .map(|entry| entry.authority.principal_id.to_string())
            .collect()
    }

    /// Read a cross-account UI device preference (theme/locale/...), shared by
    /// every account on this browser. `None` when unset.
    pub fn device_pref(&self, key: &str) -> Option<String> {
        self.read_root().device_prefs.values.get(key).cloned()
    }

    /// Set a cross-account UI device preference. Lives in the root index, not
    /// any account entry; written through storage so it is visible to every
    /// clone immediately.
    pub fn set_device_pref(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        self.mutate_root(|root| {
            root.device_prefs.values.insert(key, value);
        });
    }

    /// Record the active account's primary personal handle (e.g. `david`). The
    /// per-account entry is the single source of truth for the account
    /// selector's display label.
    pub fn set_primary_handle(&mut self, handle: &str) {
        self.ensure_cached_loaded();
        let handle = handle.trim();
        if self.cached.primary_handle != handle {
            self.cached.primary_handle = handle.to_owned();
            let _ = self.flush();
        }
    }

    /// Record one specific account's primary handle without relying on which
    /// account happens to be active when an asynchronous lookup completes.
    pub fn set_primary_handle_for_did(&mut self, did: &str, handle: &str) {
        let Ok(principal_id) = arkret_sdk::DidCoreId::new(did.trim().to_owned()) else {
            return;
        };
        if self.active_account_matches(&principal_id) {
            self.set_primary_handle(handle);
        }
    }

    /// Read a SPECIFIC account's persisted primary handle by DID, without making
    /// that account active. Returns `None` for the active account's in-memory
    /// value too (prefers the live `cached` copy when `did` is active so an
    /// unflushed set is observed). Empty string is normalised to `None`.
    pub fn primary_handle_for_did(&self, did: &str) -> Option<String> {
        let Ok(principal_id) = arkret_sdk::DidCoreId::new(did.trim().to_owned()) else {
            return None;
        };
        if !self.active_account_matches(&principal_id) {
            return None;
        }
        let handle = self.load().primary_handle;
        (!handle.trim().is_empty()).then_some(handle)
    }

    /// Wipe every account-scoped projection field of the ACTIVE account while
    /// keeping that account's own device-level state (`local_identity`,
    /// `push_registration`, `dpop_device_key`) and session
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
        let preserved_grant = self.cached.session_grant.clone();
        let preserved_dpop = self.cached.dpop_device_key.clone();
        let preserved_recovery_material = self.cached.recovery_material_evidence.clone();
        // YOU-02-004: the MLS receive-chain overlay is account-scoped state —
        // wipe it so a stale decrypt write-back can't resurrect old snapshots.
        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
        // E7: reset the account-scoped cursor overlay alongside the receive
        // overlay so a stale cursor never leaks across account scope changes.
        self.cached = ClientLocalState {
            local_identity: preserved_identity,
            push_registration: preserved_push,
            session_grant: preserved_grant,
            dpop_device_key: preserved_dpop,
            recovery_material_evidence: preserved_recovery_material,
            ..ClientLocalState::default()
        };
        let _ = self.flush();
        self.persist_e2ee_plaintext_cache_if_ready();
    }

    /// Activate an already accepted account context. This is the sole boundary
    /// that can create an account-local namespace.
    pub fn switch_active_account(
        &mut self,
        account: &crate::config::ActiveAccountContext,
    ) -> anyhow::Result<bool> {
        self.ensure_cached_loaded();
        let namespace = account_storage_scope(&account.authority)?;
        let root = self.read_root();
        let same_authority = root
            .active_entry()
            .is_some_and(|entry| entry.authority == account.authority);
        if same_authority && root.pending_login.is_none() {
            self.mutate_root(|root| {
                root.active_profile_id = Some(account.profile_id.clone());
                root.note_known_profile(AccountIndexEntry {
                    profile_id: account.profile_id.clone(),
                    authority: account.authority.clone(),
                });
            });
            return Ok(false);
        }

        let pending = root.pending_login.is_some().then(|| self.cached.clone());
        let _ = self.flush();
        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
        self.mutate_root(|root| {
            root.pending_login = None;
            root.active_profile_id = Some(account.profile_id.clone());
            root.note_known_profile(AccountIndexEntry {
                profile_id: account.profile_id.clone(),
                authority: account.authority.clone(),
            });
        });

        let mut incoming = self.read_account_state(&namespace).unwrap_or_default();
        if let Some(mut staged) = pending {
            incoming.session_grant = staged.session_grant.take().or(incoming.session_grant);
            incoming.dpop_device_key = staged.dpop_device_key.take().or(incoming.dpop_device_key);
            incoming.local_identity = staged.local_identity.take().or(incoming.local_identity);
            incoming.pending_account_handoff = staged.pending_account_handoff.take();
            incoming.pending_principal_registration = staged.pending_principal_registration.take();
            incoming.recovery_material_evidence = staged
                .recovery_material_evidence
                .take()
                .or(incoming.recovery_material_evidence);
            if !staged.primary_handle.trim().is_empty() {
                incoming.primary_handle = staged.primary_handle;
            }
        }
        self.cached = incoming;
        self.cached_account_key = Some(namespace);
        self.loaded.store(true, Ordering::Relaxed);
        self.hydrate_e2ee_plaintext_cache_if_ready();
        self.flush()?;
        Ok(true)
    }

    /// Purge a single account's persisted state: its `…account.<did>` entry,
    /// its secure-store wrap_seed namespace (wasm), and its `known_profiles` entry.
    /// Cross-account [`DevicePrefs`] and every other account are untouched. When
    /// the purged account was active, the active pointer is cleared.
    pub fn forget_account(&mut self, profile_id: &str) {
        self.ensure_cached_loaded();
        let root = self.read_root();
        let Some(entry) = root
            .known_profiles
            .iter()
            .find(|entry| entry.profile_id == profile_id)
            .cloned()
        else {
            return;
        };
        let Ok(namespace) = account_storage_scope(&entry.authority) else {
            return;
        };
        self.delete_account_state(&namespace);
        let was_active = root.active_profile_id.as_deref() == Some(profile_id);
        self.mutate_root(|root| {
            root.forget_profile(profile_id);
            if root.active_profile_id.as_deref() == Some(profile_id) {
                root.active_profile_id = None;
            }
        });
        if was_active {
            *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
            // E7: reset the account-scoped cursor overlay alongside the receive
            // overlay so a stale cursor never leaks across account scope changes.
            self.cached = ClientLocalState::default();
            self.cached_account_key = Some(self.effective_account_key());
            self.loaded.store(true, Ordering::Relaxed);
            let _ = self.flush();
        }
    }

    /// Start a fresh pre-DID login. Any onboarding checkpoint owned by the
    /// previously-active account stays with that account and the anonymous
    /// login namespace is reset before the new callback can write into it.
    pub fn begin_pending_login(
        &mut self,
        device_id: &arkret_sdk::DeviceId,
        dpop_jkt: Option<&str>,
    ) {
        self.begin_pending_login_inner(device_id, dpop_jkt, false);
    }

    /// Whether the current account has an unfinished identity handoff fenced
    /// to this exact device and its persisted DPoP holder.
    pub fn can_resume_pending_login(&self, device_id: &arkret_sdk::DeviceId) -> bool {
        let state = self.load();
        state
            .pending_account_handoff
            .as_ref()
            .is_some_and(|handoff| {
                handoff.device_id == device_id.as_str()
                    && state.dpop_device_key.as_ref().is_some_and(|dpop| {
                        !dpop.jkt.trim().is_empty() && handoff.holder_jkt == dpop.jkt
                    })
            })
    }

    /// Move a verified unfinished handoff into the anonymous pre-DID namespace.
    /// Returns `true` when the checkpoint was preserved. A failed match starts
    /// a fresh isolated login instead, so foreign onboarding state cannot leak
    /// into the next Account Authority callback.
    pub fn resume_pending_login(&mut self, device_id: &arkret_sdk::DeviceId) -> bool {
        self.ensure_cached_loaded();
        let resume_matches = self.can_resume_pending_login(device_id);
        let pending_jkt = if resume_matches {
            self.cached
                .dpop_device_key
                .as_ref()
                .map(|record| record.jkt.clone())
        } else {
            None
        };
        let can_resume = pending_jkt.is_some();
        self.begin_pending_login_inner(device_id, pending_jkt.as_deref(), can_resume);
        can_resume
    }

    /// Record the pre-DID owner and pin the pending secure-store namespace.
    /// Onboarding fields cross the account boundary only for an explicitly
    /// verified resume; fresh login and registration always start empty.
    fn begin_pending_login_inner(
        &mut self,
        device_id: &arkret_sdk::DeviceId,
        dpop_jkt: Option<&str>,
        preserve_onboarding: bool,
    ) {
        self.ensure_cached_loaded();

        let (pending_account_handoff, pending_principal_registration) = if preserve_onboarding {
            (
                self.cached.pending_account_handoff.take(),
                self.cached.pending_principal_registration.take(),
            )
        } else {
            (None, None)
        };
        // Persist the outgoing account before changing the root owner. On a
        // fresh login its checkpoint remains account-scoped; on a verified
        // resume the two fields were intentionally removed for re-homing.
        let _ = self.flush();

        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
        let anonymous = ClientLocalState {
            pending_account_handoff,
            pending_principal_registration,
            ..ClientLocalState::default()
        };

        crate::secure_key_store::set_pending_login_device_id(Some(device_id));
        // A pre-DID transaction must not inherit the process-wide signer from
        // the account that was active before this login. The onboarding path
        // rehydrates the exact pending signer from durable storage before it
        // signs or resumes a prepared registration request.
        crate::event_signer::clear_active_device_signer();
        let pending = PendingLogin {
            device_id: device_id.clone(),
            dpop_jkt: dpop_jkt
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        };
        // Publish the transaction marker before flushing its anonymous state.
        // The last-selected account remains intact; effective_account_key()
        // gives pending_login precedence and prevents cross-account writes.
        self.mutate_root(|root| {
            root.pending_login = Some(pending);
        });
        self.cached = anonymous;
        self.cached_account_key = Some(self.effective_account_key());
        self.loaded.store(true, Ordering::Relaxed);
        let _ = self.flush();
    }

    /// The in-flight pre-DID login material, if any. Read through storage so a
    /// clone that did not itself start the sign-in still observes the pending
    /// device material (the root cause of the login race was reading a stale
    /// per-clone copy here).
    pub fn pending_login(&self) -> Option<PendingLogin> {
        self.read_root().pending_login
    }

    #[cfg(test)]
    pub fn switch_test_account(&mut self, actor: &str) -> bool {
        if actor == ANONYMOUS_ACCOUNT_NAMESPACE {
            return false;
        }
        let full_id = arkret_sdk::DidFullId::new(actor.to_owned()).unwrap();
        let principal_id = arkret_sdk::project_full_id_to_core_id(&full_id).unwrap();
        let account = crate::config::ActiveAccountContext::new(
            actor.to_owned(),
            arkret_sdk::PrincipalAuthorityKey::new(
                principal_id,
                arkret_sdk::DidCoreId::new("ak:did_core:web:principal.test".to_owned()).unwrap(),
            ),
            arkret_sdk::PrincipalResolutionProjection {
                full_id,
                method_history_head: "test-head".to_owned(),
                version_id: "1".to_owned(),
                resolution_event_ref: "test-event".to_owned(),
                updated_at: chrono::Utc::now(),
            },
            arkret_sdk::DeviceId::new("ak:device:019b0000-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
            url::Url::parse("https://principal.test").unwrap(),
        )
        .unwrap();
        let was_known = self
            .read_root()
            .known_profiles
            .iter()
            .any(|entry| entry.authority == account.authority);
        self.switch_active_account(&account).unwrap();
        !was_known
    }

    #[cfg(test)]
    pub fn active_authority_namespace_for_test(&self) -> String {
        account_storage_scope(&self.active_authority().unwrap()).unwrap()
    }

    #[cfg(test)]
    pub fn promote_accepted_context_for_test(
        &mut self,
        principal_id: &arkret_sdk::DidFullId,
    ) -> bool {
        self.switch_test_account(principal_id.as_str())
    }

    pub fn pending_principal_registration(&self) -> Option<PendingPrincipalRegistration> {
        self.load().pending_principal_registration
    }

    pub fn recovery_material_evidence(&self) -> Option<RecoveryMaterialEvidence> {
        self.load().recovery_material_evidence
    }

    pub fn set_recovery_material_evidence(
        &mut self,
        evidence: Option<RecoveryMaterialEvidence>,
    ) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        self.cached.recovery_material_evidence = evidence;
        self.flush()
    }

    pub fn pending_account_handoff(&self) -> Option<PendingAccountHandoff> {
        self.load().pending_account_handoff
    }

    pub fn set_pending_account_handoff(
        &mut self,
        handoff: Option<PendingAccountHandoff>,
    ) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        self.cached.pending_account_handoff = handoff;
        self.flush()
    }

    pub fn set_pending_principal_registration(
        &mut self,
        registration: Option<PendingPrincipalRegistration>,
    ) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        self.cached.pending_principal_registration = registration;
        self.flush()
    }

    /// Clear state after this device is explicitly revoked or reset.
    ///
    /// Distinct from `clear_account_scoped` (which is the soft path —
    /// session expired, server-switch, account-change). The split is
    /// the public surface for the G3.Y0 soft-vs-hard logout contract:
    /// soft keeps device material so the user can re-authenticate; this path
    /// deletes the revoked Event-signing identity and the independent DPoP key.
    pub fn clear_device_scoped(&mut self) {
        #[cfg(not(test))]
        {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            self.clear_device_scoped_with_secure_store(secure_store.as_ref());
        }
        #[cfg(test)]
        self.clear_device_scoped_state();
    }

    pub fn clear_device_scoped_with_secure_store(
        &mut self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) {
        if let Some(authority) = self.active_authority() {
            let user_store =
                crate::secure_key_store::UserLocalStore::new(authority.principal_id.clone());
            let _ = user_store.delete_secret(secure_store, Self::SECURE_DPOP_DEVICE_KEY);
            let _ = user_store.delete_secret(secure_store, Self::SECURE_IDENTITY_KEY);
            let _ = user_store.delete_device_identity(secure_store);
        }
        crate::event_signer::clear_active_device_signer();
        self.clear_device_scoped_state();
    }

    fn clear_device_scoped_state(&mut self) {
        self.ensure_cached_loaded();
        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
        // E7: reset the account-scoped cursor overlay alongside the receive
        // overlay so a stale cursor never leaks across account scope changes.
        self.cached = ClientLocalState::default();
        let _ = self.flush();
        self.persist_e2ee_plaintext_cache_if_ready();
    }

    /// G3.Y0 — read the persisted device DPoP key, if any.
    pub fn dpop_device_key(&self) -> Option<DpopDeviceKeyRecord> {
        self.load().dpop_device_key
    }

    /// G3.Y0 — persist (or clear via `None`) the device DPoP key.
    pub fn set_dpop_device_key(&mut self, record: Option<DpopDeviceKeyRecord>) {
        #[cfg(not(test))]
        if record.is_none() {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            if let Err(error) = active_user_local_store().and_then(|user_store| {
                user_store.delete_secret(secure_store.as_ref(), Self::SECURE_DPOP_DEVICE_KEY)
            }) {
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
                active_user_local_store()?
                    .delete_secret(secure_store, Self::SECURE_DPOP_DEVICE_KEY)?;
                None
            }
        };
        self.ensure_cached_loaded();
        self.cached.dpop_device_key = public_record.clone();
        let _ = self.flush();
        Ok(public_record)
    }

    /// Persist a pre-principal DPoP key in the transaction-scoped pending
    /// store. The pending namespace is explicit and can only be promoted to a
    /// user namespace after the Account Authority returns a principal.
    pub fn set_pending_dpop_device_key_with_secure_store(
        &mut self,
        record: Option<DpopDeviceKeyRecord>,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        pending_store: &crate::secure_key_store::PendingLocalStore,
    ) -> Result<Option<DpopDeviceKeyRecord>, crate::secure_key_store::SecureKeyStoreError> {
        let public_record = match record {
            Some(record) => {
                let json = serde_json::to_string(&record).map_err(|error| {
                    crate::secure_key_store::SecureKeyStoreError::Backend(format!(
                        "serialize pending DPoP device key record: {error}"
                    ))
                })?;
                pending_store.save_secret(secure_store, Self::SECURE_DPOP_DEVICE_KEY, &json)?;
                let mut public_record = record;
                public_record.seed_b64.clear();
                Some(public_record)
            }
            None => {
                pending_store.delete_secret(secure_store, Self::SECURE_DPOP_DEVICE_KEY)?;
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

    /// Load a pre-principal DPoP key from the explicitly selected pending
    /// transaction. This must not consult the active user scope: no principal
    /// core id exists until the Account Authority completes the binding.
    pub fn load_pending_dpop_device_key_with_secure_store(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        pending_store: &crate::secure_key_store::PendingLocalStore,
    ) -> Result<Option<DpopDeviceKeyRecord>, crate::secure_key_store::SecureKeyStoreError> {
        let Some(json) = pending_store.load_secret(secure_store, Self::SECURE_DPOP_DEVICE_KEY)?
        else {
            return Ok(None);
        };
        serde_json::from_str(&json).map(Some).map_err(|error| {
            crate::secure_key_store::SecureKeyStoreError::Backend(format!(
                "deserialize pending DPoP device key record: {error}"
            ))
        })
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

    /// Stage one scheduled-send plan entry content (encrypted envelope) from
    /// the local writer or the account-data sync projection.
    pub fn stage_scheduled_send_account_data_entry(
        &mut self,
        account_data_key: impl Into<String>,
        value: Value,
    ) {
        self.ensure_cached_loaded();
        self.cached
            .scheduled_send_account_data
            .insert(account_data_key.into(), value);
        let _ = self.flush();
    }

    pub fn remove_scheduled_send_account_data_entry(&mut self, account_data_key: &str) {
        self.ensure_cached_loaded();
        self.cached
            .scheduled_send_account_data
            .remove(account_data_key);
        if let Some(scheduled_send_id) = account_data_key
            .strip_prefix(arkret_sdk::AccountDataKey::SCHEDULED_SEND_V1)
            .and_then(|rest| rest.strip_prefix(':'))
        {
            self.cached
                .scheduled_send_target_realms
                .remove(scheduled_send_id);
        }
        let _ = self.flush();
    }

    /// The account-data sync frame carries the complete projection, so any
    /// staged scheduled-send key absent from `seen_keys` was tombstoned or
    /// deleted elsewhere and must be dropped locally.
    pub fn retain_scheduled_send_account_data_keys(
        &mut self,
        seen_keys: &std::collections::BTreeSet<String>,
    ) {
        self.ensure_cached_loaded();
        let stale: Vec<String> = self
            .cached
            .scheduled_send_account_data
            .keys()
            .filter(|key| !seen_keys.contains(*key))
            .cloned()
            .collect();
        if stale.is_empty() {
            return;
        }
        for key in stale {
            self.remove_scheduled_send_account_data_entry(&key);
        }
    }

    pub fn set_scheduled_send_target_realm(
        &mut self,
        scheduled_send_id: impl Into<String>,
        realm_id: impl Into<String>,
    ) {
        self.ensure_cached_loaded();
        self.cached
            .scheduled_send_target_realms
            .insert(scheduled_send_id.into(), realm_id.into());
        let _ = self.flush();
    }

    pub fn scheduled_send_target_realm(&self, scheduled_send_id: &str) -> Option<String> {
        self.load()
            .scheduled_send_target_realms
            .get(scheduled_send_id)
            .cloned()
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
        // Read through `load()` (like `snapshot_sync_status`) so a
        // freshly-constructed store whose `cached` has not yet been populated
        // still reports the durable pending count instead of a spurious 0.
        self.load().pending_encrypted_messages.len()
    }
}
