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
        // YOU-02-004: order this write after any decrypt write-backs so the
        // overlay can never shadow it (overlay snapshots always derive from
        // the state this caller just read via `mls_snapshot_for`).
        self.absorb_mls_receive_overlay();
        self.cached.mls_snapshots.insert(realm_id.into(), envelope);
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
        self.load().mls_snapshots.get(realm_id).cloned()
    }

    /// Snapshot of every persisted MLS envelope. Used by the boot
    /// path to rehydrate every known Realm's group in one pass and by
    /// device-recovery flows to enumerate the encrypted snapshots that
    /// can be restored for this device.
    pub fn mls_snapshots(&self) -> BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope> {
        self.load().mls_snapshots
    }

    /// Drop the MLS snapshot for a Realm — used after a successful
    /// "rotate group" / "leave group" Move so the next boot doesn't
    /// try to rehydrate a stale leaf.
    pub fn drop_mls_snapshot(&mut self, realm_id: &str) {
        self.absorb_mls_receive_overlay();
        let dropped_snapshot = self.cached.mls_snapshots.remove(realm_id).is_some();
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
        self.mls_decrypt_serial.lock().unwrap()
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
            let overlay = self.mls_receive_overlay.lock().unwrap();
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
            let mut overlay = self.mls_receive_overlay.lock().unwrap();
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
        self.load().mls_genesis_emitted.contains(realm_id)
    }

    /// Record that a `ck.mls.genesis` event has been submitted for this
    /// Realm so it is never re-emitted (idempotent).
    pub fn mark_mls_genesis_emitted(&mut self, realm_id: impl Into<String>) {
        self.ensure_cached_loaded();
        if self.cached.mls_genesis_emitted.insert(realm_id.into()) {
            let _ = self.flush();
        }
    }

    /// X5.1 — persist the author's own plaintext for an encrypted private
    /// flow field into the local-only sidecar. `field_path` is the dotted
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
        flow_id: &str,
        field_path: &str,
        plaintext: &str,
    ) {
        let realm_id = realm_id.trim();
        let flow_id = flow_id.trim();
        let field_path = field_path.trim();
        if realm_id.is_empty() || flow_id.is_empty() || field_path.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let mut changed = false;
        if plaintext.is_empty() {
            // Cleared field: drop the sidecar entry (and prune empty maps).
            if let Some(flows) = self.cached.mls_private_plaintext.get_mut(realm_id)
                && let Some(fields) = flows.get_mut(flow_id)
            {
                if fields.remove(field_path).is_some() {
                    changed = true;
                }
                if fields.is_empty() {
                    flows.remove(flow_id);
                }
            }
            if let Some(flows) = self.cached.mls_private_plaintext.get(realm_id)
                && flows.is_empty()
            {
                self.cached.mls_private_plaintext.remove(realm_id);
            }
        } else {
            let slot = self
                .cached
                .mls_private_plaintext
                .entry(realm_id.to_owned())
                .or_default()
                .entry(flow_id.to_owned())
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
    /// ever stored for this (Realm, flow, field) — the read path then
    /// falls back to decrypting another member's ciphertext.
    pub fn private_plaintext_for(
        &self,
        realm_id: &str,
        flow_id: &str,
        field_path: &str,
    ) -> Option<String> {
        self.load()
            .mls_private_plaintext
            .get(realm_id.trim())
            .and_then(|flows| flows.get(flow_id.trim()))
            .and_then(|fields| fields.get(field_path.trim()))
            .filter(|plaintext| !plaintext.is_empty())
            .cloned()
    }

    /// X5.1 — all sidecar plaintext fields for a single flow (`field_path
    /// -> plaintext`). Convenience for callers that want to enumerate
    /// every stored field at once.
    pub fn private_plaintext_fields(
        &self,
        realm_id: &str,
        flow_id: &str,
    ) -> BTreeMap<String, String> {
        self.load()
            .mls_private_plaintext
            .get(realm_id.trim())
            .and_then(|flows| flows.get(flow_id.trim()))
            .cloned()
            .unwrap_or_default()
    }

    /// X5.3 — serialize the ENTIRE local-plaintext sidecar map
    /// (`realm -> flow -> field -> plaintext`) to JSON bytes for the encrypted
    /// cross-device backup. Returns the serialization of an empty map (`{}`)
    /// when no sidecar entries exist, so callers can cheaply detect "nothing to
    /// back up" via [`Self::private_plaintext_is_empty`] first.
    pub fn private_plaintext_snapshot_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.load().mls_private_plaintext).unwrap_or_else(|_| b"{}".to_vec())
    }

    /// X5.3 — true when the sidecar holds no plaintext for any Realm/flow/field.
    /// Used to skip the cross-device backup upload when there is nothing to
    /// protect.
    pub fn private_plaintext_is_empty(&self) -> bool {
        self.load().mls_private_plaintext.is_empty()
    }

    /// X5.3 — merge an incoming sidecar map (decrypted from a cross-device
    /// backup) into the local cache, then flush.
    ///
    /// Merge semantics: incoming entries only FILL fields that are missing
    /// locally; on a (Realm, flow, field) conflict the EXISTING LOCAL value is
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
        for (realm_id, flows) in incoming {
            let local_flows = self
                .cached
                .mls_private_plaintext
                .entry(realm_id)
                .or_default();
            for (flow_id, fields) in flows {
                let local_fields = local_flows.entry(flow_id).or_default();
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
}
