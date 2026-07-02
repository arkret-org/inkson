use super::*;

impl LocalStateStore {
    // ── MLS group state persistence ─────────────────────────────────

    /// Persist (or replace) the MLS snapshot envelope for a Realm.
    /// Idempotent: a re-snapshot at the same epoch overwrites the
    /// previous record. The on-disk envelope is opaque to soland —
    /// device-secret-derived encryption keeps the server zero-knowledge
    /// of the underlying group keys.
    pub fn save_mls_snapshot(
        &mut self,
        realm_id: impl Into<String>,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
    ) {
        self.save_mls_snapshot_for_effective_scope(realm_id, None, envelope);
    }

    pub fn save_mls_snapshot_for_effective_scope(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
    ) {
        // YOU-02-004: order this write after any decrypt write-backs so the
        // overlay can never shadow it (overlay snapshots always derive from
        // the state this caller just read via `mls_snapshot_for`).
        self.absorb_mls_receive_overlay();
        let realm_id = realm_id.into();
        let key = mls_effective_scope_snapshot_key(&realm_id, circle_id);
        self.cached.mls_snapshots.insert(key, envelope);
        let _ = self.flush();
    }

    /// Look up the latest MLS snapshot envelope for a Realm, if any.
    /// Returns `None` when the Realm has not yet been snapshotted (a
    /// fresh group on this device, or a group that has not committed
    /// yet so there is no state to persist).
    pub fn mls_snapshot_for(
        &self,
        realm_id: &str,
    ) -> Option<crate::mls::persistence::MlsSnapshotEnvelope> {
        self.mls_snapshot_for_effective_scope(realm_id, None)
    }

    pub fn mls_snapshot_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> Option<crate::mls::persistence::MlsSnapshotEnvelope> {
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        self.load().mls_snapshots.get(&key).cloned()
    }

    // ── MLS history-secret persistence (history sharing) ────────────

    /// Install a per-(realm, epoch) MLS `history_secret` recovered from an
    /// inbound `ck.realm_key.share`. Idempotent: a re-install at the same
    /// `(realm, epoch)` overwrites with the (identical) secret. Empty secrets
    /// are ignored so a malformed share can never shadow a real key.
    pub fn save_history_secret(
        &mut self,
        realm_id: impl Into<String>,
        epoch: u64,
        secret: Vec<u8>,
    ) {
        if secret.is_empty() {
            return;
        }
        let realm_id = realm_id.into();
        // E2EE-at-rest: route raw history key material to the hardened secure
        // store instead of plaintext account-state JSON. If the secure store is
        // unavailable, keep only the in-memory fallback for this process.
        let mut by_epoch =
            crate::secure_key_store::load_realm_history_secrets(&realm_id).unwrap_or_default();
        by_epoch.insert(epoch, secret.clone());
        if crate::secure_key_store::persist_realm_history_secrets(&realm_id, &by_epoch) {
            return;
        }
        self.cached
            .history_secrets
            .entry(realm_id)
            .or_default()
            .insert(epoch, secret);
        let _ = self.flush();
    }

    /// All installed `history_secret`s for `realm_id`, as `(epoch, secret)`
    /// pairs ordered by epoch. Used by the tier-3 history decrypt retry to
    /// try every granted epoch key against a pre-join ciphertext.
    pub fn history_secrets_for(&self, realm_id: &str) -> Vec<(u64, Vec<u8>)> {
        let realm_id = realm_id.trim();
        let mut merged: BTreeMap<u64, Vec<u8>> =
            crate::secure_key_store::load_realm_history_secrets(realm_id).unwrap_or_default();
        if let Some(inline) = self.load().history_secrets.get(realm_id) {
            for (epoch, secret) in inline {
                merged.entry(*epoch).or_insert_with(|| secret.clone());
            }
        }
        merged.into_iter().collect()
    }

    /// The installed `history_secret` for an exact `(realm, epoch)`, if any.
    pub fn history_secret_for(&self, realm_id: &str, epoch: u64) -> Option<Vec<u8>> {
        let realm_id = realm_id.trim();
        // E2EE-at-rest: prefer the hardened secure store, falling back to a
        // same-process inline entry only when durable secure storage is
        // unavailable.
        if let Some(by_epoch) = crate::secure_key_store::load_realm_history_secrets(realm_id)
            && let Some(secret) = by_epoch.get(&epoch)
        {
            return Some(secret.clone());
        }
        self.load()
            .history_secrets
            .get(realm_id)
            .and_then(|by_epoch| by_epoch.get(&epoch))
            .cloned()
    }

    /// Snapshot of every persisted MLS envelope. Used by the boot
    /// path to rehydrate every known Realm's group in one pass and by
    /// device-recovery strands to enumerate the encrypted snapshots that
    /// can be restored for this device.
    pub fn mls_snapshots(&self) -> BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope> {
        self.load().mls_snapshots
    }

    /// Drop the MLS snapshot for a Realm — used after a successful
    /// "rotate group" / "leave group" Move so the next boot doesn't
    /// try to rehydrate a stale leaf.
    pub fn drop_mls_snapshot(&mut self, realm_id: &str) {
        self.drop_mls_snapshot_for_effective_scope(realm_id, None);
    }

    pub fn drop_mls_snapshot_for_effective_scope(
        &mut self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) {
        self.absorb_mls_receive_overlay();
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        let dropped_snapshot = self.cached.mls_snapshots.remove(&key).is_some();
        // The decrypted-plaintext cache is keyed to ciphertext minted under
        // the dropped group state; it stays readable history (same lifetime
        // policy as the author sidecar) and is NOT wiped here.
        if dropped_snapshot {
            let _ = self.flush();
        }
    }

    // ── YOU-02-004: MLS receive-chain persistence + plaintext cache ──
    //
    // `encryption-and-audit.md` §5.6 (normative): after every successful
    // decrypt of an application message the advanced MLS group state MUST
    // be persisted — the ratchet must never be replayed from an earlier
    // snapshot on the next decrypt. These entry points are deliberately
    // `&self` (interior mutability through [`MlsReceiveOverlay`]) because
    // the decrypt-on-read callers run inside render passes that only hold
    // a read borrow of the `Signal<LocalStateStore>`.

    /// Acquire the receive-chain serialization guard. The caller holds it
    /// across the whole restore→decrypt→export→[`Self::advance_mls_receive_chain`]
    /// sequence so concurrent views can't both advance the same group from
    /// the same base snapshot.
    pub fn mls_decrypt_serial_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock_mls_decrypt_serial()
    }

    /// Look up a previously decrypted plaintext by the envelope's canonical
    /// `payload_digest`. Render paths consult this BEFORE attempting an MLS
    /// decrypt — after the receive chain advanced past a message, this cache
    /// is the only way to re-render it.
    pub fn mls_decrypted_plaintext_for(
        &self,
        realm_id: &str,
        payload_digest: &str,
    ) -> Option<Vec<u8>> {
        use base64::Engine as _;
        let encoded = {
            let overlay = self.lock_mls_receive_overlay();
            overlay
                .plaintexts
                .get(realm_id)
                .and_then(|entries| entries.get(payload_digest))
                .cloned()
        };
        let encoded = match encoded {
            Some(encoded) => encoded,
            None => self
                .load()
                .mls_decrypted_plaintext
                .get(realm_id)?
                .get(payload_digest)?
                .clone(),
        };
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .ok()
    }

    /// Drop a cached remote-member MLS plaintext by payload digest.
    pub fn drop_mls_decrypted_plaintext(&mut self, realm_id: &str, payload_digest: &str) -> bool {
        let realm_id = realm_id.trim();
        let payload_digest = payload_digest.trim();
        if realm_id.is_empty() || payload_digest.is_empty() {
            return false;
        }
        self.absorb_mls_receive_overlay();
        let changed = remove_decrypted_plaintext_entry(
            &mut self.cached.mls_decrypted_plaintext,
            realm_id,
            payload_digest,
        );
        if changed {
            let _ = self.flush();
        }
        changed
    }

    /// Drop local plaintext retained for a disappearing message.
    ///
    /// This removes the author's sidecar (`message:<message_id>`) and, when the
    /// encrypted envelope digest is known, the remote decrypt cache entry.
    pub fn drop_disappearing_message_plaintext(
        &mut self,
        realm_id: &str,
        strand_id: &str,
        message_id: &str,
        payload_digest: Option<&str>,
    ) -> bool {
        let realm_id = realm_id.trim();
        let strand_id = strand_id.trim();
        let message_id = message_id.trim();
        if realm_id.is_empty() || strand_id.is_empty() || message_id.is_empty() {
            return false;
        }
        self.absorb_mls_receive_overlay();
        let field_path = if message_id.starts_with("message:") {
            message_id.to_owned()
        } else {
            format!("message:{message_id}")
        };
        let mut changed = remove_private_plaintext_entry(
            &mut self.cached.mls_private_plaintext,
            realm_id,
            strand_id,
            &field_path,
        );
        if let Some(payload_digest) = payload_digest
            .map(str::trim)
            .filter(|payload_digest| !payload_digest.is_empty())
        {
            changed |= remove_decrypted_plaintext_entry(
                &mut self.cached.mls_decrypted_plaintext,
                realm_id,
                payload_digest,
            );
        }
        if changed {
            let _ = self.flush();
        }
        changed
    }

    /// Persist a successful decrypt: the advanced (post-decrypt) snapshot
    /// envelope AND the decrypted plaintext (cached under `payload_digest`).
    /// Both are recorded through the shared overlay and immediately flushed
    /// to the backing store, so a restart never replays the ratchet from
    /// the pre-decrypt snapshot (§5.6 MUST) and the message stays readable.
    pub fn advance_mls_receive_chain(
        &self,
        realm_id: &str,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
        payload_digest: &str,
        plaintext: &[u8],
    ) {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext);
        {
            let mut overlay = self.lock_mls_receive_overlay();
            overlay.snapshots.insert(realm_id.to_owned(), envelope);
            overlay
                .plaintexts
                .entry(realm_id.to_owned())
                .or_default()
                .insert(payload_digest.to_owned(), encoded);
        }
        // Persist NOW (merged via `effective_state_for_persist`). Failures
        // are latched into `persist_health` like every other persist; the
        // overlay still holds the advancement in memory so the session
        // itself never regresses.
        let _ = self.flush();
    }

    /// True once a `ck.mls.genesis` event has been submitted for this Realm.
    pub fn mls_genesis_emitted_for(&self, realm_id: &str) -> bool {
        self.mls_genesis_emitted_for_effective_scope(realm_id, None)
    }

    pub fn mls_genesis_emitted_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> bool {
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        self.load().mls_genesis_emitted.contains(&key)
    }

    /// Record that a `ck.mls.genesis` event has been submitted for this
    /// Realm so it is never re-emitted (idempotent).
    pub fn mark_mls_genesis_emitted(&mut self, realm_id: impl Into<String>) {
        self.mark_mls_genesis_emitted_for_effective_scope(realm_id, None);
    }

    /// Record a successfully accepted `ck.mls.genesis` event and seed the
    /// local MLS group-state frontier with that accepted Event id. This lets an
    /// immediately-following self-update or AddMember commit cite a real
    /// `ck:event:*` base group-state ref before the next sync response arrives.
    pub fn mark_mls_genesis_emitted_with_event(
        &mut self,
        realm_id: impl Into<String>,
        genesis_event_id: &cokret_sdk::EventId,
    ) {
        self.mark_mls_genesis_emitted_for_effective_scope_with_event(
            realm_id,
            None,
            genesis_event_id,
        );
    }

    pub fn mark_mls_genesis_emitted_for_effective_scope(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let key = mls_effective_scope_snapshot_key(&realm_id, circle_id);
        if self.cached.mls_genesis_emitted.insert(key) {
            let _ = self.flush();
        }
    }

    pub fn mark_mls_genesis_emitted_for_effective_scope_with_event(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        genesis_event_id: &cokret_sdk::EventId,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let key = mls_effective_scope_snapshot_key(&realm_id, circle_id);
        let mut changed = self.cached.mls_genesis_emitted.insert(key);
        if circle_id.is_none() {
            let event_ref = genesis_event_id.as_str().to_owned();
            let view = self.cached.seal_views.entry(realm_id).or_default();
            if !view.frontier.iter().any(|value| value == &event_ref) {
                view.frontier.push(event_ref);
                view.frontier.sort();
                view.frontier.dedup();
                changed = true;
            }
            if view.mls_epoch != Some(0) {
                view.mls_epoch = Some(0);
                changed = true;
            }
        }
        if changed {
            let _ = self.flush();
        }
    }

    /// X5.1 — persist the author's own plaintext for an encrypted private
    /// strand field into the local-only sidecar. `field_path` is the dotted
    /// private patch path (e.g. `"body"`, `"synthesis"`); `plaintext` is
    /// the JSON-serialized patch value the writer encrypted. Empty values
    /// are removed rather than stored so a cleared field doesn't keep a
    /// stale plaintext around (consistent with the `unset` write path).
    ///
    /// This data NEVER leaves the device — it is the only place the
    /// author's own encrypted content survives a re-projection, since the
    /// author can never decrypt their own MLS ciphertext.
    pub fn save_private_plaintext(
        &mut self,
        realm_id: &str,
        strand_id: &str,
        field_path: &str,
        plaintext: &str,
    ) {
        let realm_id = realm_id.trim();
        let strand_id = strand_id.trim();
        let field_path = field_path.trim();
        if realm_id.is_empty() || strand_id.is_empty() || field_path.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let mut changed = false;
        if plaintext.is_empty() {
            // Cleared field: drop the sidecar entry (and prune empty maps).
            if let Some(strands) = self.cached.mls_private_plaintext.get_mut(realm_id)
                && let Some(fields) = strands.get_mut(strand_id)
            {
                if fields.remove(field_path).is_some() {
                    changed = true;
                }
                if fields.is_empty() {
                    strands.remove(strand_id);
                }
            }
            if let Some(strands) = self.cached.mls_private_plaintext.get(realm_id)
                && strands.is_empty()
            {
                self.cached.mls_private_plaintext.remove(realm_id);
            }
        } else {
            let slot = self
                .cached
                .mls_private_plaintext
                .entry(realm_id.to_owned())
                .or_default()
                .entry(strand_id.to_owned())
                .or_default()
                .entry(field_path.to_owned())
                .or_default();
            if *slot != plaintext {
                *slot = plaintext.to_owned();
                changed = true;
            }
        }
        if changed {
            let _ = self.flush();
        }
    }

    /// X5.1 — read back a single author-owned plaintext field from the
    /// local sidecar, if present. Returns `None` when no plaintext was
    /// ever stored for this (Realm, strand, field) — the read path then
    /// falls back to decrypting another member's ciphertext.
    pub fn private_plaintext_for(
        &self,
        realm_id: &str,
        strand_id: &str,
        field_path: &str,
    ) -> Option<String> {
        self.load()
            .mls_private_plaintext
            .get(realm_id.trim())
            .and_then(|strands| strands.get(strand_id.trim()))
            .and_then(|fields| fields.get(field_path.trim()))
            .filter(|plaintext| !plaintext.is_empty())
            .cloned()
    }

    /// X5.1 — all sidecar plaintext fields for a single strand (`field_path
    /// -> plaintext`). Convenience for callers that want to enumerate
    /// every stored field at once.
    pub fn private_plaintext_fields(
        &self,
        realm_id: &str,
        strand_id: &str,
    ) -> BTreeMap<String, String> {
        self.load()
            .mls_private_plaintext
            .get(realm_id.trim())
            .and_then(|strands| strands.get(strand_id.trim()))
            .cloned()
            .unwrap_or_default()
    }

    /// X5.3 — serialize the ENTIRE local-plaintext sidecar map
    /// (`realm -> strand -> field -> plaintext`) to JSON bytes for the encrypted
    /// cross-device backup. Returns the serialization of an empty map (`{}`)
    /// when no sidecar entries exist, so callers can cheaply detect "nothing to
    /// back up" via [`Self::private_plaintext_is_empty`] first.
    pub fn private_plaintext_snapshot_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.load().mls_private_plaintext).unwrap_or_else(|_| b"{}".to_vec())
    }

    /// X5.3 — true when the sidecar holds no plaintext for any Realm/strand/field.
    /// Used to skip the cross-device backup upload when there is nothing to
    /// protect.
    pub fn private_plaintext_is_empty(&self) -> bool {
        self.load().mls_private_plaintext.is_empty()
    }

    /// X5.3 — merge an incoming sidecar map (decrypted from a cross-device
    /// backup) into the local cache, then flush.
    ///
    /// Merge semantics: incoming entries only FILL fields that are missing
    /// locally; on a (Realm, strand, field) conflict the EXISTING LOCAL value is
    /// kept. Rationale: the local sidecar is written synchronously on every
    /// encrypted write by the author on THIS device, so a locally-present value
    /// is at least as fresh as the backup (which is only re-uploaded
    /// periodically). On a brand-new browser the local cache is empty, so the
    /// backup populates everything — the common restore case.
    pub fn merge_private_plaintext_map(
        &mut self,
        incoming: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    ) {
        if incoming.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let mut changed = false;
        for (realm_id, strands) in incoming {
            let local_strands = self
                .cached
                .mls_private_plaintext
                .entry(realm_id)
                .or_default();
            for (strand_id, fields) in strands {
                let local_fields = local_strands.entry(strand_id).or_default();
                for (field_path, plaintext) in fields {
                    if plaintext.is_empty() {
                        continue;
                    }
                    // Keep existing local value on conflict; only fill gaps.
                    local_fields.entry(field_path).or_insert_with(|| {
                        changed = true;
                        plaintext
                    });
                }
            }
        }
        if changed {
            let _ = self.flush();
        }
    }

    /// The genesis-locked MLS `policy_root` for this Realm's group, if recorded.
    ///
    /// See [`crate::local_state::types::PersistedState::mls_genesis_policy_root`]:
    /// every `ck.mls.commit` MUST declare the exact `policy_root` that
    /// `ck.mls.genesis` locked, or soland rejects it with
    /// `governance_binding_mismatch`. Commit builders read this so they reuse the
    /// locked bytes instead of recomputing from the moving Seal `state_root`.
    pub fn genesis_policy_root_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> Option<String> {
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        self.load().mls_genesis_policy_root.get(&key).cloned()
    }

    /// Record the genesis-locked MLS `policy_root` for this Realm's group.
    ///
    /// First-writer-wins: the value is locked at genesis and never changes for
    /// the life of the group (soland carries it forward unchanged), so a later
    /// call with a drifted root MUST NOT overwrite the genuine genesis value.
    pub fn record_genesis_policy_root_for_effective_scope(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        policy_root: &str,
    ) {
        let policy_root = policy_root.trim();
        if policy_root.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let key = mls_effective_scope_snapshot_key(&realm_id.into(), circle_id);
        if self.cached.mls_genesis_policy_root.contains_key(&key) {
            return;
        }
        self.cached
            .mls_genesis_policy_root
            .insert(key, policy_root.to_owned());
        let _ = self.flush();
    }
}

pub(crate) fn mls_effective_scope_snapshot_key(realm_id: &str, circle_id: Option<&str>) -> String {
    match circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty())
    {
        Some(circle_id) => circle_id.to_owned(),
        None => realm_id.to_owned(),
    }
}

fn remove_decrypted_plaintext_entry(
    plaintexts: &mut BTreeMap<String, BTreeMap<String, String>>,
    realm_id: &str,
    payload_digest: &str,
) -> bool {
    let Some(entries) = plaintexts.get_mut(realm_id) else {
        return false;
    };
    let changed = entries.remove(payload_digest).is_some();
    if entries.is_empty() {
        plaintexts.remove(realm_id);
    }
    changed
}

fn remove_private_plaintext_entry(
    plaintexts: &mut BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    realm_id: &str,
    strand_id: &str,
    field_path: &str,
) -> bool {
    let Some(strands) = plaintexts.get_mut(realm_id) else {
        return false;
    };
    let Some(fields) = strands.get_mut(strand_id) else {
        return false;
    };
    let changed = fields.remove(field_path).is_some();
    if fields.is_empty() {
        strands.remove(strand_id);
    }
    if strands.is_empty() {
        plaintexts.remove(realm_id);
    }
    changed
}
