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
            if let Some(record) = load_identity_record_from_secure_store(secure_store.as_ref()) {
                return Some(record);
            }
            if !plaintext_identity_seed_fallback_allowed() {
                return None;
            }
        }
        self.load().local_identity
    }

    /// Replace (or clear) the persisted device identity record. Used by
    /// the [`crate::key_store::KeyStore`] trait's `save_identity` impl so
    /// a future Keychain / Secret-Service backend can hand a different
    /// record back to the in-memory cache without going through
    /// `ensure_local_identity` (which would generate a fresh seed if the
    /// record was missing).
    pub fn set_local_identity_record(&mut self, record: Option<LocalIdentityRecord>) {
        self.ensure_cached_loaded();
        #[cfg(target_arch = "wasm32")]
        if record.is_some() && !plaintext_identity_seed_fallback_allowed() {
            tracing::warn!("refusing to persist wasm local identity seed in plaintext local state");
            self.cached.local_identity = None;
            let _ = self.flush();
            return;
        }
        self.cached.local_identity = record;
        let _ = self.flush();
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

        #[cfg(target_arch = "wasm32")]
        if self.cached.local_identity.is_some() {
            tracing::warn!("discarding wasm plaintext local identity seed instead of migrating it");
            self.cached.local_identity = None;
            let _ = self.flush();
        }

        #[cfg(not(target_arch = "wasm32"))]
        if let Some(record) = self.cached.local_identity.clone() {
            let identity = LocalIdentity::from_record(&record)?;
            match store_identity_record_in_secure_store(secure_store, &record) {
                Ok(()) => {
                    self.cached.local_identity = None;
                    let _ = self.flush();
                    return Ok(identity);
                }
                Err(error) if plaintext_identity_seed_fallback_allowed() => {
                    tracing::warn!(
                        ?error,
                        "secure identity handoff failed; using explicit plaintext identity fallback",
                    );
                    return Ok(identity);
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "secure identity handoff failed and plaintext identity fallback is disabled: {error}"
                    ));
                }
            }
        }

        let identity = LocalIdentity::generate()?;
        let record = identity.to_record();
        match store_identity_record_in_secure_store(secure_store, &record) {
            Ok(()) => {
                self.cached.local_identity = None;
                let _ = self.flush();
                Ok(identity)
            }
            Err(error) if plaintext_identity_seed_fallback_allowed() => {
                tracing::warn!(
                    ?error,
                    "secure identity store unavailable; using explicit plaintext identity fallback",
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

    /// Persist (or clear via `None`) the coauth `session_grant`.
    pub fn set_session_grant(&mut self, grant: Option<PersistedSessionGrant>) {
        self.ensure_cached_loaded();
        self.cached.session_grant = grant;
        let _ = self.flush();
    }

    /// Clear only browser-session credentials for a user-initiated logout.
    ///
    /// This is deliberately narrower than [`Self::clear_account_scoped`]: a
    /// hard browser re-login must rotate the grant-binding/DPoP key while
    /// preserving the account's durable E2EE state (MLS snapshots, sidecars,
    /// projections, and device identity) so the same account can continue
    /// decrypting and writing after it signs in again.
    pub fn clear_session_scoped_for_logout(&mut self) {
        #[cfg(not(test))]
        {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            if let Err(error) = secure_store.delete_secret(
                &crate::secure_key_store::account_scoped_device_key(Self::SECURE_DPOP_DEVICE_KEY),
            ) {
                tracing::debug!(
                    ?error,
                    "secure_key_store DPoP key delete on logout failed (likely already missing)",
                );
            }
        }
        self.ensure_cached_loaded();
        self.cached.session_grant = None;
        self.cached.dpop_device_key = None;
        let _ = self.flush();
    }

    /// Append a structured user-action log entry to the buffered telemetry
    /// log. Bounded by [`TELEMETRY_BUFFER_CAP`] - excess entries are
    /// dropped from the front (oldest-first).
    pub fn append_telemetry(&mut self, entry: UserActionLogEntry) {
        self.ensure_cached_loaded();
        self.cached.telemetry_log.push(entry);
        let overflow = self
            .cached
            .telemetry_log
            .len()
            .saturating_sub(TELEMETRY_BUFFER_CAP);
        if overflow > 0 {
            self.cached.telemetry_log.drain(0..overflow);
        }
        let _ = self.flush();
    }

    /// Read-only snapshot of the buffered telemetry entries.
    pub fn telemetry_log(&self) -> Vec<UserActionLogEntry> {
        self.load().telemetry_log
    }

    /// Drain the buffered telemetry entries — returns the existing
    /// entries and clears the on-disk buffer atomically. Called by the
    /// flush path once a network channel is available.
    pub fn drain_telemetry(&mut self) -> Vec<UserActionLogEntry> {
        self.ensure_cached_loaded();
        let drained = std::mem::take(&mut self.cached.telemetry_log);
        let _ = self.flush();
        drained
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
    /// [`obfuscate_nonsensitive`]): `account_key` is the public account DID, so
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
