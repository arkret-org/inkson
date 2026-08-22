use super::*;

impl LocalStateStore {
    /// The authenticated foreground account authority. A pending sign-in has
    /// its own anonymous transaction namespace, so this returns `None` while
    /// that transaction is active even though the selected profile is retained.
    pub fn active_account_authority(&self) -> Option<arkret_sdk::PrincipalAuthorityKey> {
        let root = self.read_root();
        if root.pending_login.is_some() {
            return None;
        }
        root.active_profile_id
            .as_deref()
            .and_then(|profile_id| root.authority_for_profile(profile_id))
            .cloned()
    }

    pub fn active_profile_id(&self) -> Option<String> {
        let root = self.read_root();
        root.pending_login
            .is_none()
            .then_some(root.active_profile_id)
            .flatten()
    }

    /// Last profile selected on this installation. This survives sign-in
    /// failure/cancellation and is never used as authority for the pending
    /// transaction.
    pub fn last_selected_profile_id(&self) -> Option<String> {
        self.read_root().active_profile_id
    }

    pub fn active_account_matches(&self, authority: &arkret_sdk::PrincipalAuthorityKey) -> bool {
        self.active_account_authority().as_ref() == Some(authority)
    }

    pub fn known_profile_refs(&self) -> Vec<KnownProfileRef> {
        self.read_root().known_profiles
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
        let Some(authority) = self.active_account_authority() else {
            return;
        };
        self.set_primary_handle_for_authority(&authority, handle);
    }

    /// Record one specific account's primary handle without relying on which
    /// account happens to be active when an asynchronous lookup completes.
    pub fn set_primary_handle_for_authority(
        &mut self,
        authority: &arkret_sdk::PrincipalAuthorityKey,
        handle: &str,
    ) {
        let handle = handle.trim();
        let is_active = self.active_account_matches(authority);
        if is_active {
            self.ensure_cached_loaded();
            if self.cached.primary_handle == handle {
                return;
            }
            self.cached.primary_handle = handle.to_owned();
            let _ = self.flush();
            return;
        }

        let Ok(scope) = account_storage_scope(authority) else {
            return;
        };
        let mut state = self.read_account_state(&scope).unwrap_or_default();
        if state.primary_handle == handle {
            return;
        }
        state.primary_handle = handle.to_owned();
        let _ = self.write_account_state(&scope, &state);
    }

    /// Read a SPECIFIC account's persisted primary handle by DID, without making
    /// that account active. Returns `None` for the active account's in-memory
    /// value too (prefers the live `cached` copy when `did` is active so an
    /// unflushed set is observed). Empty string is normalised to `None`.
    pub fn primary_handle_for_authority(
        &self,
        authority: &arkret_sdk::PrincipalAuthorityKey,
    ) -> Option<String> {
        let scope = account_storage_scope(authority).ok()?;
        let handle =
            if self.loaded.load(Ordering::Relaxed) && self.active_account_matches(authority) {
                self.cached.primary_handle.clone()
            } else {
                self.read_account_state(&scope)
                    .map(|state| state.primary_handle)
                    .unwrap_or_default()
            };
        (!handle.trim().is_empty()).then_some(handle)
    }

    /// Register `did` as a known account in the selector index (idempotent).
    /// Does not change the active account. The account's `device_id` /
    /// `server_url` for the selector come from its persisted `session_grant`
    /// (written by the login state persistence), so they need not be passed here.
    pub fn register_known_profile(
        &mut self,
        profile_id: &str,
        authority: &arkret_sdk::PrincipalAuthorityKey,
    ) {
        let _ = self.mutate_root(|root| root.note_known_profile(profile_id, authority));
    }

    /// Enumerate the accounts known on this browser for the signed-out account
    /// selector: each account's DID, its display handle (when resolved), and the
    /// `(device_id, server_url)` it last signed in with (read from that
    /// account's own persisted entry — never the active account's). The handle
    /// is always preferred for display; callers must never render the raw DID.
    pub fn known_accounts(&self) -> Vec<KnownAccount> {
        let root = self.read_root();
        root.known_profiles
            .iter()
            .map(|known| {
                // Read the account's own entry; prefer the live `cached` copy
                // for the active account so an unflushed login is reflected.
                let state = if self.loaded.load(Ordering::Relaxed)
                    && self.active_account_matches(&known.authority)
                {
                    Some(self.cached.clone())
                } else {
                    account_storage_scope(&known.authority)
                        .ok()
                        .and_then(|scope| self.read_account_state(&scope))
                };
                let (handle, device_id, server_url) = match state {
                    Some(state) => {
                        let grant = state.session_grant.as_ref();
                        (
                            state.primary_handle,
                            grant.map(|g| g.device_id.clone()),
                            grant.and_then(|g| url::Url::parse(&g.principal_server_url).ok()),
                        )
                    }
                    None => (String::new(), None, None),
                };
                KnownAccount {
                    profile_id: known.profile_id.clone(),
                    authority: known.authority.clone(),
                    handle,
                    device_id,
                    server_url,
                }
            })
            .collect()
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

    /// Make one typed profile/authority pair active, loading its account entry.
    /// Account isolation is structural (one key per account), so switching is
    /// re-pointing the persisted active profile and swapping `cached` for the
    /// target account's persisted entry — never wiping another account's data.
    ///
    /// Ordering matters for correctness across clones: `mutate_root` lands the
    /// new active profile in storage FIRST, then `cached` is hydrated from the
    /// target entry, then `flush()` persists `cached` — at which point
    /// `effective_account_key` reads back the just-written authority, so the
    /// blob lands under the right authority-digest key.
    ///
    /// Returns `true` when the active account actually changed.
    pub fn switch_active_account(
        &mut self,
        profile_id: &str,
        authority: &arkret_sdk::PrincipalAuthorityKey,
    ) -> bool {
        self.ensure_cached_loaded();
        let profile_id = profile_id.trim();
        if profile_id.is_empty() {
            return false;
        }
        let current_active = self.read_root().active_profile_id;
        if current_active.as_deref() == Some(profile_id) && self.active_account_matches(authority) {
            // Already active — just make sure it's recorded as known.
            self.mutate_root(|root| {
                root.note_known_profile(profile_id, authority);
            });
            return false;
        }
        // Persist the outgoing account's entry before swapping so nothing is
        // lost. The outgoing entry is selected by the CURRENT (pre-switch)
        // active profile, so flush while that still points at the old account.
        // Phase 2 (wasm): flush freezes the durable write under the OUTGOING
        // account key before the root index switches, so the incoming account's
        // single-writer queue never inherits the leaving account's queued state.
        let _ = self.flush();
        *self.lock_mls_receive_overlay() = MlsReceiveOverlay::default();
        // E7: reset the account-scoped cursor overlay alongside the receive
        // overlay so a stale cursor never leaks across account scope changes.
        // Land the new active pointer in shared storage first.
        let activated_profile_id = self.mutate_root(|root| {
            let activated_profile_id = root.note_known_profile(profile_id, authority);
            if let Some(profile_id) = &activated_profile_id {
                root.active_profile_id = Some(profile_id.clone());
            }
            activated_profile_id
        });
        let Some(activated_profile_id) = activated_profile_id else {
            return false;
        };
        // Load the target account's own entry (default for a brand-new account).
        self.cached = account_storage_scope(authority)
            .ok()
            .and_then(|scope| self.read_account_state(&scope))
            .unwrap_or_default();
        debug_assert_eq!(
            self.read_root().active_profile_id.as_deref(),
            Some(activated_profile_id.as_str())
        );
        self.cached_account_key = Some(self.effective_account_key());
        self.loaded.store(true, Ordering::Relaxed);
        self.hydrate_e2ee_plaintext_cache_if_ready();
        // Flush `cached` under the now-active account's key.
        let _ = self.flush();
        true
    }

    /// Purge a single account's persisted state: its `…account.<did>` entry,
    /// its secure-store namespace (wasm), and its `known_profiles` entry.
    /// Cross-account [`DevicePrefs`] and every other account are untouched. When
    /// the purged account was active, the active pointer is cleared.
    pub fn forget_account(
        &mut self,
        profile_id: &str,
        authority: &arkret_sdk::PrincipalAuthorityKey,
    ) {
        self.ensure_cached_loaded();
        let profile_id = profile_id.trim();
        if profile_id.is_empty() {
            return;
        }
        if let Ok(scope) = account_storage_scope(authority) {
            self.delete_account_state(&scope);
        }
        let was_active = self.read_root().active_profile_id.as_deref() == Some(profile_id);
        self.mutate_root(|root| {
            root.forget_known_profile(profile_id);
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

    /// Adopt the pending pre-DID login onto the resolved principal `did`
    /// (session grant has returned the DID). Two outcomes:
    ///
    /// * `did` already has a persisted entry (a returning account on this browser) -> load that
    ///   account's entry without wiping its projections. Returns `false` (not a new account).
    /// * `did` is new on this browser -> activate a default entry for the new account. Returns
    ///   `true` (new account).
    ///
    /// Either way the pending root entry is cleared and `did` becomes active.
    /// The pending local store is promoted into a typed `UserLocalStore` before
    /// this is called. Returning users retain their existing device identity.
    pub fn adopt_pending_login(&mut self, account: &crate::config::ActiveAccountContext) -> bool {
        self.ensure_cached_loaded();
        let full_id = account.resolution.full_id.as_str();
        let anonymous_onboarding = self.read_account_state(ANONYMOUS_ACCOUNT_NAMESPACE);
        let pending_registration = anonymous_onboarding
            .as_ref()
            .and_then(|state| state.pending_principal_registration.clone())
            .filter(|registration| registration.full_id.as_str() == full_id);
        let anonymous_account_handoff = anonymous_onboarding
            .as_ref()
            .and_then(|state| state.pending_account_handoff.clone());
        let pending_account_handoff = anonymous_account_handoff.clone().filter(|handoff| {
            pending_registration
                .as_ref()
                .is_some_and(|registration| registration.handoff_request_id == handoff.request_id)
        });
        let is_returning_account = self
            .read_root()
            .known_profiles
            .iter()
            .any(|known| known.authority == account.authority)
            || account_storage_scope(&account.authority)
                .ok()
                .and_then(|scope| self.read_account_state(&scope))
                .is_some();
        // Clear pending namespace pin before the seed-scope adopt re-homes it,
        // and clear the persisted `pending_login` (shared through storage, not a
        // per-clone field) so no stale clone resurrects it on a later flush.
        crate::secure_key_store::set_pending_login_device_id(None);
        self.mutate_root(|root| root.pending_login = None);
        self.switch_active_account(&account.profile_id, &account.authority);
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
        } else if let Some(handoff) = anonymous_account_handoff {
            // Keep the returning handoff recoverable until the caller commits
            // the account-scoped key and session state. Move it out of the
            // anonymous namespace first; successful login completion clears it
            // from the active account, while a mid-commit failure can resume.
            self.cached.pending_account_handoff = Some(handoff);
            if self.flush().is_ok()
                && let Some(mut anonymous) = anonymous_onboarding
            {
                anonymous.pending_account_handoff = None;
                let _ = self.write_account_state(ANONYMOUS_ACCOUNT_NAMESPACE, &anonymous);
            }
        }
        !is_returning_account
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
        if let Some(scope) = crate::secure_key_store::active_device_seed_scope()
            && let Ok(user_store) =
                crate::secure_key_store::UserLocalStore::new(scope.authority, scope.device_id)
        {
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
