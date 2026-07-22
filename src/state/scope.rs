use super::*;

impl LocalStateStore {
    /// The currently-active account DID (the foreground account whose entry
    /// `cached` mirrors), or `None` when signed out / before any account has
    /// been adopted on this browser. Read through storage so every clone agrees.
    pub fn active_account_did(&self) -> Option<String> {
        self.read_root().active_did
    }

    /// Every account DID with a persisted per-account entry on this browser.
    pub fn known_account_dids(&self) -> Vec<String> {
        self.read_root().known_dids
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
        let did = self.effective_account_key();
        self.set_primary_handle_for_did(&did, handle);
    }

    /// Record one specific account's primary handle without relying on which
    /// account happens to be active when an asynchronous lookup completes.
    pub fn set_primary_handle_for_did(&mut self, did: &str, handle: &str) {
        let did = did.trim();
        if did.is_empty() {
            return;
        }
        let handle = handle.trim();
        let is_active = self.read_root().active_did.as_deref() == Some(did);
        if is_active {
            self.ensure_cached_loaded();
            if self.cached.primary_handle == handle {
                return;
            }
            self.cached.primary_handle = handle.to_owned();
            let _ = self.flush();
            return;
        }

        let mut state = self.read_account_state(did).unwrap_or_default();
        if state.primary_handle == handle {
            return;
        }
        state.primary_handle = handle.to_owned();
        let _ = self.write_account_state(did, &state);
    }

    /// Read a SPECIFIC account's persisted primary handle by DID, without making
    /// that account active. Returns `None` for the active account's in-memory
    /// value too (prefers the live `cached` copy when `did` is active so an
    /// unflushed set is observed). Empty string is normalised to `None`.
    pub fn primary_handle_for_did(&self, did: &str) -> Option<String> {
        let did = did.trim();
        if did.is_empty() {
            return None;
        }
        let handle = if self.loaded.load(Ordering::Relaxed)
            && self.read_root().active_did.as_deref() == Some(did)
        {
            self.cached.primary_handle.clone()
        } else {
            self.read_account_state(did)
                .map(|state| state.primary_handle)
                .unwrap_or_default()
        };
        (!handle.trim().is_empty()).then_some(handle)
    }

    /// Register `did` as a known account in the selector index (idempotent).
    /// Does not change the active account. The account's `device_id` /
    /// `server_url` for the selector come from its persisted `session_grant`
    /// (written by the login state persistence), so they need not be passed here.
    pub fn register_known_account(&mut self, did: &str) {
        let did = did.trim();
        if did.is_empty() {
            return;
        }
        self.mutate_root(|root| root.note_known_did(did));
    }

    /// Enumerate the accounts known on this browser for the signed-out account
    /// selector: each account's DID, its display handle (when resolved), and the
    /// `(device_id, server_url)` it last signed in with (read from that
    /// account's own persisted entry — never the active account's). The handle
    /// is always preferred for display; callers must never render the raw DID.
    pub fn known_accounts(&self) -> Vec<KnownAccount> {
        let root = self.read_root();
        let active = root.active_did.clone();
        root.known_dids
            .iter()
            .map(|did| {
                // Read the account's own entry; prefer the live `cached` copy
                // for the active account so an unflushed login is reflected.
                let state = if self.loaded.load(Ordering::Relaxed)
                    && active.as_deref() == Some(did.as_str())
                {
                    Some(self.cached.clone())
                } else {
                    self.read_account_state(did)
                };
                let (handle, device_id, server_url) = match state {
                    Some(state) => {
                        let grant = state.session_grant.as_ref();
                        (
                            state.primary_handle,
                            grant.map(|g| g.device_id.clone()).unwrap_or_default(),
                            grant
                                .map(|g| g.principal_server_url.clone())
                                .unwrap_or_default(),
                        )
                    }
                    None => (String::new(), String::new(), String::new()),
                };
                KnownAccount {
                    did: did.clone(),
                    handle,
                    device_id,
                    server_url,
                }
            })
            .collect()
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
        // E7: reset the account-scoped cursor overlay alongside the receive
        // overlay so a stale cursor never leaks across account scope changes.
        self.cached = ClientLocalState {
            local_identity: preserved_identity,
            push_registration: preserved_push,
            telemetry_log: preserved_telemetry,
            session_grant: preserved_grant,
            dpop_device_key: preserved_dpop,
            ..ClientLocalState::default()
        };
        let _ = self.flush();
        self.persist_e2ee_plaintext_cache_if_ready();
    }

    /// Make `actor` the active account, loading its own per-account entry.
    /// Account isolation is structural (one key per account), so switching is
    /// re-pointing the persisted `active_did` and swapping `cached` for the
    /// target account's persisted entry — never wiping another account's data.
    ///
    /// Ordering matters for correctness across clones: `mutate_root` lands the
    /// new `active_did` in storage FIRST, then `cached` is hydrated from the
    /// target entry, then `flush()` persists `cached` — at which point
    /// `effective_account_key` reads back the just-written `active_did`, so the
    /// blob lands under the right `…account.<did>` key.
    ///
    /// Returns `true` when the active account actually changed.
    pub fn switch_active_account(&mut self, actor: &str) -> bool {
        self.ensure_cached_loaded();
        let actor = actor.trim();
        if actor.is_empty() {
            return false;
        }
        let current_active = self.read_root().active_did;
        if current_active.as_deref() == Some(actor) {
            // Already active — just make sure it's recorded as known.
            self.mutate_root(|root| root.note_known_did(actor));
            return false;
        }
        // Persist the outgoing account's entry before swapping so nothing is
        // lost. The outgoing entry is selected by the CURRENT (pre-switch)
        // `active_did`, so flush while that still points at the old account.
        // Phase 2 (wasm): flush freezes the durable write under the OUTGOING
        // account key before the root index switches, so the incoming account's
        // single-writer queue never inherits the leaving account's queued state.
        let _ = self.flush();
        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
        // E7: reset the account-scoped cursor overlay alongside the receive
        // overlay so a stale cursor never leaks across account scope changes.
        // Land the new active pointer in shared storage first.
        self.mutate_root(|root| {
            root.active_did = Some(actor.to_owned());
            root.note_known_did(actor);
        });
        // Load the target account's own entry (default for a brand-new account).
        self.cached = self.read_account_state(actor).unwrap_or_default();
        self.hydrate_e2ee_plaintext_cache_if_ready();
        // Flush `cached` under the now-active account's key.
        let _ = self.flush();
        true
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
        let was_active = self.read_root().active_did.as_deref() == Some(actor);
        self.mutate_root(|root| {
            root.forget_known_did(actor);
            if root.active_did.as_deref() == Some(actor) {
                root.active_did = None;
            }
        });
        if was_active {
            *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
            // E7: reset the account-scoped cursor overlay alongside the receive
            // overlay so a stale cursor never leaks across account scope changes.
            self.cached = ClientLocalState::default();
            let _ = self.flush();
        }
    }

    /// Start a fresh pre-DID login. Any onboarding checkpoint owned by the
    /// previously-active account stays with that account and the anonymous
    /// login namespace is reset before the new callback can write into it.
    pub fn begin_pending_login(&mut self, device_id: &str, dpop_jkt: Option<&str>) {
        self.begin_pending_login_inner(device_id, dpop_jkt, false);
    }

    /// Whether the current account has an unfinished identity handoff fenced
    /// to this exact device and its persisted DPoP holder.
    pub fn can_resume_pending_login(&self, device_id: &str) -> bool {
        let state = self.load();
        let device_id = device_id.trim();
        state
            .pending_account_handoff
            .as_ref()
            .is_some_and(|handoff| {
                !device_id.is_empty()
                    && handoff.device_id == device_id
                    && state.dpop_device_key.as_ref().is_some_and(|dpop| {
                        !dpop.jkt.trim().is_empty() && handoff.holder_jkt == dpop.jkt
                    })
            })
    }

    /// Move a verified unfinished handoff into the anonymous pre-DID namespace.
    /// Returns `true` when the checkpoint was preserved. A failed match starts
    /// a fresh isolated login instead, so foreign onboarding state cannot leak
    /// into the next Account Authority callback.
    pub fn resume_pending_login(&mut self, device_id: &str) -> bool {
        self.ensure_cached_loaded();
        let device_id = device_id.trim();
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
        device_id: &str,
        dpop_jkt: Option<&str>,
        preserve_onboarding: bool,
    ) {
        let device_id = device_id.trim();
        if device_id.is_empty() {
            return;
        }
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
        let pending = PendingLogin {
            device_id: device_id.to_owned(),
            dpop_jkt: dpop_jkt
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        };
        // Publish the anonymous owner before flushing its state so the generic
        // persistence path cannot route this snapshot back into the old DID.
        self.mutate_root(|root| {
            root.active_did = None;
            root.pending_login = Some(pending);
        });
        self.cached = anonymous;
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

    /// Adopt the pending pre-DID login onto the resolved principal `did`
    /// (session grant has returned the DID). Two outcomes:
    ///
    /// * `did` already has a persisted entry (a returning account on this browser) -> load that
    ///   account's entry without wiping its projections. Returns `false` (not a new account).
    /// * `did` is new on this browser -> activate a default entry for the new account. Returns
    ///   `true` (new account).
    ///
    /// Either way the pending root entry is cleared and `did` becomes active.
    /// The secure-store device seed/device_id scope selection itself is handled
    /// by `adopt_device_seed_scope_on_login` before this is called; returning
    /// accounts keep their existing device identity while first-time accounts may
    /// adopt bootstrap material.
    pub fn adopt_pending_login(&mut self, did: &str) -> bool {
        self.ensure_cached_loaded();
        let did = did.trim();
        if did.is_empty() {
            return false;
        }
        let anonymous_onboarding = self.read_account_state(ANONYMOUS_ACCOUNT_NAMESPACE);
        let pending_registration = anonymous_onboarding
            .as_ref()
            .and_then(|state| state.pending_principal_registration.clone())
            .filter(|registration| registration.did == did);
        let pending_account_handoff = anonymous_onboarding
            .as_ref()
            .and_then(|state| state.pending_account_handoff.clone())
            .filter(|handoff| {
                pending_registration.as_ref().is_some_and(|registration| {
                    registration.handoff_request_id == handoff.request_id
                })
            });
        let is_returning_account = self.read_root().known_dids.iter().any(|known| known == did)
            || self.read_account_state(did).is_some();
        // Clear pending namespace pin before the seed-scope adopt re-homes it,
        // and clear the persisted `pending_login` (shared through storage, not a
        // per-clone field) so no stale clone resurrects it on a later flush.
        crate::secure_key_store::set_pending_login_device_id(None);
        self.mutate_root(|root| root.pending_login = None);
        self.switch_active_account(did);
        if let Some(registration) = pending_registration {
            self.cached.pending_principal_registration = Some(registration);
            self.cached.pending_account_handoff = pending_account_handoff;
            if self.flush().is_ok()
                && let Some(mut anonymous) = self.read_account_state(ANONYMOUS_ACCOUNT_NAMESPACE)
            {
                anonymous.pending_principal_registration = None;
                anonymous.pending_account_handoff = None;
                let _ = self.write_account_state(ANONYMOUS_ACCOUNT_NAMESPACE, &anonymous);
            }
        }
        !is_returning_account
    }

    pub fn pending_principal_registration(&self) -> Option<PendingPrincipalRegistration> {
        self.load().pending_principal_registration
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
            return;
        }
        #[cfg(test)]
        self.clear_device_scoped_state();
    }

    pub fn clear_device_scoped_with_secure_store(
        &mut self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) {
        let account = self.active_account_did();
        let _ =
            secure_store.delete_secret(&crate::secure_key_store::account_scoped_device_key_for(
                Self::SECURE_DPOP_DEVICE_KEY,
                account.as_deref(),
            ));
        let _ = secure_store.delete_secret(Self::SECURE_IDENTITY_KEY);
        let _ = crate::secure_key_store::delete_grant_binding_seed(secure_store);
        if let Some(account) = account.as_deref() {
            let _ = crate::secure_key_store::delete_device_identity_scope(secure_store, account);
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
                secure_store.delete_secret(&crate::secure_key_store::account_scoped_device_key(
                    Self::SECURE_DPOP_DEVICE_KEY,
                ))?;
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
