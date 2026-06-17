use super::*;

impl LocalStateStore {
    /// R3.1 MID-2 — record inlined `ck.member.identity.update` event
    /// envelopes harvested off a `members[]` roster entry. Idempotent
    /// on event id; events that already exist for this `(realm, actor)`
    /// pair are skipped. The runtime
    /// [`crate::member_identity_store::MemberIdentityStore`] is rebuilt
    /// from these envelopes on demand.
    pub fn ingest_member_identity_events(
        &mut self,
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        events: &[Value],
    ) {
        if events.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let actor_id = actor_id.into();
        let bucket = self
            .cached
            .member_identity_events
            .entry(realm_id)
            .or_default()
            .entry(actor_id)
            .or_default();
        for event in events {
            let Some(event_id) = event.get("event_id").and_then(Value::as_str) else {
                continue;
            };
            let kind = event.get("kind").and_then(Value::as_str).unwrap_or("");
            if kind != "ck.member.identity.update" {
                continue;
            }
            let already = bucket.iter().any(|existing| {
                existing
                    .get("event_id")
                    .and_then(Value::as_str)
                    .is_some_and(|existing_id| existing_id == event_id)
            });
            if !already {
                bucket.push(event.clone());
            }
        }
        let _ = self.flush();
    }

    /// R3.1 MID-3 — return the resolved [`cokret_sdk::MemberIdentity`]
    /// for `(realm_id, actor_id)`, or `None` when no plaintext identity
    /// has been observed (decryption pending or no events ingested
    /// yet). UI surfaces SHOULD fall back to a muted placeholder when
    /// [`is_member_decryption_pending`] returns `true`, and to the
    /// compact DID otherwise.
    pub fn resolved_member_identity(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> Option<cokret_sdk::MemberIdentity> {
        let envelopes = self.member_identity_envelopes(realm_id, actor_id);
        if envelopes.is_empty() {
            return None;
        }
        let mut store = crate::member_identity_store::MemberIdentityStore::new();
        store.ingest_inline(realm_id, actor_id, &envelopes);
        store.current_identity(realm_id, actor_id)
    }

    /// R3.1 MID-6 — `true` when the actor has at least one identity
    /// event but every effective event is `decryption_pending` (the
    /// MLS group state needed to decrypt the carrier has not yet
    /// arrived). UI surfaces a muted placeholder rather than the raw
    /// DID in this state.
    pub fn is_member_decryption_pending(&self, realm_id: &str, actor_id: &str) -> bool {
        let envelopes = self.member_identity_envelopes(realm_id, actor_id);
        if envelopes.is_empty() {
            return false;
        }
        let mut store = crate::member_identity_store::MemberIdentityStore::new();
        store.ingest_inline(realm_id, actor_id, &envelopes);
        store.is_decryption_pending(realm_id, actor_id)
    }

    /// Return a fresh cached primary handle lookup for a subject in a Realm
    /// display context. `Some(entry)` with `entry.primary_handle == None` is
    /// a fresh negative cache entry; callers should not immediately re-query.
    pub fn cached_member_handle_lookup(
        &self,
        subject_id: &str,
        realm_id: Option<&str>,
        member_display_state_digest: Option<&str>,
    ) -> Option<MemberHandleCacheEntry> {
        let subject_id = subject_id.trim();
        if subject_id.is_empty() {
            return None;
        }
        let state = self.load();
        let key = member_handle_cache_key(subject_id, realm_id);
        let entry = state.member_handle_cache.get(&key)?;
        if entry.cache_expires_at <= Utc::now() {
            return None;
        }
        if let Some(expected) = member_display_state_digest
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match entry.member_display_state_digest.as_deref() {
                Some(cached) if cached == expected => {}
                _ => return None,
            }
        }
        Some(entry.clone())
    }

    /// Save a display-only `list_handles_for_subject` result. The cache TTL
    /// is capped at one hour, and additionally capped by the earliest visible
    /// claim expiry when the response supplies one. Empty results use a short
    /// negative-cache TTL so a render loop does not hammer the Directory.
    pub fn save_member_handle_lookup(
        &mut self,
        subject_id: impl Into<String>,
        realm_id: Option<String>,
        member_display_state_digest: Option<String>,
        primary_handle: Option<String>,
        claims_count: usize,
        as_of: Option<DateTime<Utc>>,
        earliest_claim_expires_at: Option<DateTime<Utc>>,
    ) {
        self.ensure_cached_loaded();
        let subject_id = subject_id.into();
        let subject_id = subject_id.trim();
        if subject_id.is_empty() {
            return;
        }
        let realm_id = realm_id
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let primary_handle = primary_handle
            .and_then(|value| crate::identity_handle::parse_user_handle(&value).map(|h| h.display));
        let now = Utc::now();
        let ttl = if primary_handle.is_some() || claims_count > 0 {
            MEMBER_HANDLE_CACHE_TTL_SECONDS
        } else {
            MEMBER_HANDLE_NEGATIVE_CACHE_TTL_SECONDS
        };
        let mut cache_expires_at = now + chrono::Duration::seconds(ttl);
        if let Some(claim_expiry) = earliest_claim_expires_at
            && claim_expiry > now
            && claim_expiry < cache_expires_at
        {
            cache_expires_at = claim_expiry;
        }
        let entry = MemberHandleCacheEntry {
            subject_id: subject_id.to_owned(),
            realm_id: realm_id.clone(),
            primary_handle,
            claims_count,
            fetched_at: now,
            as_of,
            cache_expires_at,
            member_display_state_digest: member_display_state_digest
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
        };
        let key = member_handle_cache_key(subject_id, realm_id.as_deref());
        self.cached.member_handle_cache.insert(key, entry);
        let _ = self.flush();
    }

    fn member_identity_envelopes(&self, realm_id: &str, actor_id: &str) -> Vec<Value> {
        self.cached
            .member_identity_events
            .get(realm_id)
            .and_then(|by_actor| by_actor.get(actor_id))
            .cloned()
            .unwrap_or_default()
    }
}
