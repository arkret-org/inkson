use super::*;

impl LocalStateStore {
    /// Look up the persisted device identity record without generating
    /// a fresh one. Returns `None` when the device hasn't been initialised
    /// yet (e.g. fresh install before `ensure_local_identity` has been
    /// called).
    pub fn local_identity_record(&self) -> Option<LocalIdentityRecord> {
        #[cfg(not(test))]
        {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            load_identity_record_from_secure_store(secure_store.as_ref())
        }
        // The plaintext `local_identity` member of the persisted state is a
        // unit-test carrier only; a shipped build never reads an identity seed
        // from it (see `plaintext_identity_seed_fallback_allowed`).
        #[cfg(test)]
        {
            self.load().local_identity
        }
    }

    /// Read the in-memory device identity. Returns `None` when no record
    /// is persisted; callers that need a key should call
    /// [`Self::ensure_local_identity`] which generates + persists on first
    /// access. Distinct from `ensure_*` so callers that only want to
    /// **observe** an existing identity (e.g. status UI) don't trigger a
    /// write.
    pub fn local_identity(&self) -> Option<LocalIdentity> {
        self.local_identity_record()
            .as_ref()
            .and_then(|record| LocalIdentity::from_record(record).ok())
    }

    /// Load — or generate + persist — the device identity. First call on
    /// a fresh install fills `getrandom::fill` 32-byte seed, derives the
    /// `did:key`, and writes the record to disk. Subsequent calls return
    /// the persisted identity. If the persisted record is malformed (e.g.
    /// hand-edited or truncated) this regenerates and overwrites — the
    /// alternative is bricking the client, and Arkret v1 is pre-release
    /// so there is no user-facing key recovery story to preserve.
    pub fn ensure_local_identity(&mut self) -> anyhow::Result<LocalIdentity> {
        #[cfg(not(test))]
        {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            self.ensure_local_identity_with_secure_store(secure_store.as_ref())
        }
        #[cfg(test)]
        {
            self.ensure_local_identity_in_plaintext_state()
        }
    }

    pub fn ensure_local_identity_with_secure_store(
        &mut self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<LocalIdentity> {
        self.ensure_cached_loaded();
        if let Some(record) = load_identity_record_from_secure_store(secure_store) {
            return LocalIdentity::from_record(&record);
        }

        if self.cached.local_identity.is_some() {
            tracing::warn!("discarding plaintext local identity seed");
            self.cached.local_identity = None;
            let _ = self.flush();
        }

        let identity = LocalIdentity::generate()?;
        let record = identity.to_record();
        match store_identity_record_in_secure_store(secure_store, &record) {
            Ok(()) => {
                self.cached.local_identity = None;
                let _ = self.flush();
                Ok(identity)
            }
            // Unit tests only — `plaintext_identity_seed_fallback_allowed()` is
            // `cfg!(test)`, so a shipped build always takes the `Err` arm below.
            Err(error) if plaintext_identity_seed_fallback_allowed() => {
                tracing::warn!(
                    ?error,
                    "secure identity store unavailable; using the test-only plaintext identity fallback",
                );
                self.cached.local_identity = Some(record);
                let _ = self.flush();
                Ok(identity)
            }
            Err(error) => Err(anyhow::anyhow!(
                "secure identity store unavailable and plaintext identity fallback is disabled: {error}"
            )),
        }
    }

    #[cfg(test)]
    pub(super) fn ensure_local_identity_in_plaintext_state(
        &mut self,
    ) -> anyhow::Result<LocalIdentity> {
        self.ensure_cached_loaded();
        if let Some(record) = self.cached.local_identity.as_ref() {
            match LocalIdentity::from_record(record) {
                Ok(id) => return Ok(id),
                Err(err) => {
                    tracing::warn!("local_identity record corrupted ({err}); regenerating");
                }
            }
        }
        let identity = LocalIdentity::generate()?;
        self.cached.local_identity = Some(identity.to_record());
        let _ = self.flush();
        Ok(identity)
    }

    /// Read the persisted coauth `session_grant` if any.
    pub fn session_grant(&self) -> Option<PersistedSessionGrant> {
        self.load().session_grant
    }

    /// Publish (or clear via `None`) the live coauth `session_grant`.
    ///
    /// Account-state snapshots intentionally strip credentials. Callers that
    /// install a grant must durably write it to an explicit `UserLocalStore`
    /// before calling this setter; this method never guesses a secure-store
    /// target from process-global scope.
    pub fn set_session_grant(&mut self, grant: Option<PersistedSessionGrant>) {
        self.ensure_cached_loaded();
        self.cached.session_grant = grant;
        let _ = self.flush();
    }

    /// Clear only browser-session credentials for a user-initiated logout.
    ///
    /// This is deliberately narrower than [`Self::clear_account_scoped`]: a
    /// hard browser re-login must rotate the grant-binding/DPoP key while
    /// preserving the account's encrypted E2EE checkpoint, projections, and
    /// device identity so the same account can continue decrypting and writing
    /// after it signs in again. Plaintext sidecars are cleared from memory and
    /// restored from the encrypted checkpoint only after the next sign-in.
    pub fn clear_session_scoped_for_logout(&mut self) {
        #[cfg(not(test))]
        {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            match active_user_local_store() {
                Ok(user_store) => {
                    if let Err(error) = user_store
                        .delete_secret(secure_store.as_ref(), Self::SECURE_DPOP_DEVICE_KEY)
                    {
                        tracing::debug!(?error, "secure DPoP key delete on logout failed");
                    }
                    if let Err(error) = user_store
                        .delete_secret(secure_store.as_ref(), Self::SECURE_SESSION_GRANT_KEY)
                    {
                        tracing::debug!(?error, "secure session grant delete on logout failed");
                    }
                    if let Err(error) = user_store.delete_grant_binding_seed(secure_store.as_ref())
                    {
                        tracing::debug!(?error, "grant-binding seed delete on logout failed");
                    }
                }
                Err(error) => {
                    tracing::debug!(?error, "logout had no active user local store");
                }
            }
        }
        self.ensure_cached_loaded();
        self.cached.session_grant = None;
        self.cached.dpop_device_key = None;
        self.clear_e2ee_plaintext_from_memory();
        let _ = self.flush();
    }

    pub fn push_registration(&self) -> Option<PushRegistrationState> {
        self.load().push_registration
    }

    pub fn save_push_registration(&mut self, state: PushRegistrationState) {
        self.ensure_cached_loaded();
        self.cached.push_registration = Some(state);
        let _ = self.flush();
    }

    pub fn clear_push_registration(&mut self) {
        self.ensure_cached_loaded();
        self.cached.push_registration = None;
        let _ = self.flush();
    }

    /// Save a **non-sensitive** UI preference, XOR-obfuscated with the account
    /// key. This is obfuscation, not encryption (see
    /// [`obfuscate_nonsensitive`]): `account_key` is a public local storage locator, so
    /// this MUST NOT be used for secret material — only casual-plaintext-hiding
    /// of preferences.
    pub fn save_private_data(
        &mut self,
        account_key: &str,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        self.ensure_cached_loaded();
        let plaintext = value.into();
        let obfuscated = obfuscate_nonsensitive(account_key, &plaintext);
        self.cached.private_data.insert(key.into(), obfuscated);
        let _ = self.flush();
    }

    /// Load and de-obfuscate a non-sensitive UI preference.
    pub fn load_private_data(&self, account_key: &str, key: &str) -> Option<String> {
        let obfuscated = self.load().private_data.get(key)?.clone();
        deobfuscate_nonsensitive(account_key, &obfuscated)
    }

    /// Remove a private preference.
    pub fn remove_private_data(&mut self, key: &str) {
        self.ensure_cached_loaded();
        self.cached.private_data.remove(key);
        let _ = self.flush();
    }

    /// List all private data keys.
    pub fn private_data_keys(&self) -> Vec<String> {
        self.load().private_data.keys().cloned().collect()
    }
}
