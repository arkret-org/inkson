//! R3.2 — Realm-scoped `cx.member.identity.update` event store.
//!
//! Spec source: cokret-spec @ b56cab1 (2026-05-28)
//! `models/member-identity.md` + `artifacts/schemas/member-identity.schema.json`.
//!
//! Sync ingest pipeline (MID-2): when a `members[]` roster entry on an
//! `account.subscribe` frame inlines `identity_events[]` (or references
//! events that already arrived via `state.events`), the renderer copies
//! the raw envelopes into [`MemberIdentityStore`] keyed by
//! `(realm_id, actor_id, segment)`. The effective set is computed via
//! the SDK's [`contrix_sdk::effective_identity_events`] helper (MID-3).
//!
//! MID-4 (MLS decryption) + MID-5 (proof signature verification) are
//! `TODO(R4)` — the typed wire surface + the effective-set + carrier
//! digest binding (MID-3) are all in place so the UI can resolve the
//! effective `MemberIdentity` (subject_id + display_profile) as soon as
//! the crypto pipeline lands. Handle now comes from the
//! `cx.schema.handle_claim.v1` set via §3.2.1 primary handle selection —
//! `MemberIdentity` no longer carries `primary_handle` / `handles[]`.

use std::collections::BTreeMap;

use contrix_sdk::{
    Did, EventId, IdentityPayloadCarrier, MemberIdentity, MemberIdentitySegment,
    MemberIdentityUpdatePayload, RealmId, effective_identity_events,
};
use serde_json::Value;

/// Per-actor key on the store. `(realm_id, actor_id)` — the segment
/// (`member_identity`) is implicit at v1.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActorKey {
    pub realm_id: String,
    pub actor_id: String,
}

/// Stored `cx.member.identity.update` event record. Carries the parsed
/// SDK payload + the raw envelope (so we can re-hash it for replacement
/// edge verification). `decryption_pending` is set when the carrier was
/// an `encrypted_content` envelope we couldn't decrypt yet (missing MLS epoch).
#[derive(Clone, Debug)]
pub struct StoredIdentityEvent {
    pub event_id: String,
    pub payload: MemberIdentityUpdatePayload,
    pub decryption_pending: bool,
}

/// Per-(realm, actor) collection of `cx.member.identity.update` event
/// records. Keyed by event id; insertion is idempotent.
#[derive(Clone, Debug, Default)]
pub struct MemberIdentityStore {
    inner: BTreeMap<ActorKey, BTreeMap<String, StoredIdentityEvent>>,
}

impl MemberIdentityStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// MID-2 — record a `cx.member.identity.update` event for a given
    /// actor. Idempotent on `event_id`.
    pub fn insert(&mut self, key: ActorKey, event: StoredIdentityEvent) {
        self.inner
            .entry(key)
            .or_default()
            .insert(event.event_id.clone(), event);
    }

    /// Bulk-ingest a roster-inlined `identity_events[]` array. Each
    /// entry MUST be a full Event envelope shaped per
    /// `artifacts/schemas/event.schema.json` — i.e. with `event_id`,
    /// `kind == "cx.member.identity.update"`, and a `payload` body that
    /// deserialises into [`MemberIdentityUpdatePayload`].
    ///
    /// Events that fail to parse are silently skipped (we don't crash
    /// the sync loop on a malformed payload); production code SHOULD
    /// surface a structured warning via `last_error`.
    pub fn ingest_inline(&mut self, realm_id: &str, actor_id: &str, identity_events: &[Value]) {
        for event in identity_events {
            let Some(event_id) = event
                .get("event_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let kind = event.get("kind").and_then(Value::as_str).unwrap_or("");
            if kind != "cx.member.identity.update" {
                continue;
            }
            let Some(payload_value) = event.get("payload") else {
                continue;
            };
            // MID-4 hook: the carrier can be plaintext or encrypted. We
            // try to decode as `MemberIdentityUpdatePayload`; if the
            // `identity_payload` is an `encrypted_content` envelope we still get
            // a valid typed value back (the `untagged` enum picks the
            // right arm), but the inner `MemberIdentity` is unavailable.
            let Ok(payload) =
                serde_json::from_value::<MemberIdentityUpdatePayload>(payload_value.clone())
            else {
                continue;
            };
            let decryption_pending = matches!(
                payload.identity_payload,
                IdentityPayloadCarrier::EncryptedContent { .. },
            );
            self.insert(
                ActorKey {
                    realm_id: realm_id.to_owned(),
                    actor_id: actor_id.to_owned(),
                },
                StoredIdentityEvent {
                    event_id,
                    payload,
                    decryption_pending,
                },
            );
        }
    }

    /// MID-3 — compute the current effective [`MemberIdentity`] for a
    /// `(realm, actor)`. Applies the SDK's replacement-edge filter and
    /// returns the most recently asserted plaintext identity, or `None`
    /// when every effective event is still `decryption_pending`.
    pub fn current_identity(&self, realm_id: &str, actor_id: &str) -> Option<MemberIdentity> {
        let key = ActorKey {
            realm_id: realm_id.to_owned(),
            actor_id: actor_id.to_owned(),
        };
        let stored = self.inner.get(&key)?;
        let sdk_realm_id = RealmId::new(realm_id).ok()?;
        let sdk_actor_id = Did::new(actor_id.to_owned()).ok()?;

        // Build the (EventId, &Payload) candidate list the SDK helper
        // expects. Drop entries whose event_id won't parse.
        let mut owned: Vec<(EventId, &MemberIdentityUpdatePayload, bool)> = Vec::new();
        for (event_id_str, stored_event) in stored.iter() {
            if let Ok(event_id) = EventId::new(event_id_str.to_owned()) {
                // Filter by (realm, actor, segment) per the helper's
                // contract.
                if stored_event.payload.realm_id != sdk_realm_id
                    || stored_event.payload.actor_id != sdk_actor_id
                    || !matches!(
                        stored_event.payload.segment,
                        MemberIdentitySegment::MemberIdentity
                    )
                {
                    continue;
                }
                owned.push((
                    event_id,
                    &stored_event.payload,
                    stored_event.decryption_pending,
                ));
            }
        }
        if owned.is_empty() {
            return None;
        }
        let candidates: Vec<(&EventId, &MemberIdentityUpdatePayload)> = owned
            .iter()
            .map(|(event_id, payload, _)| (event_id, *payload))
            .collect();
        let effective = effective_identity_events(candidates).ok()?;

        // Map effective events back to their original index so we can
        // look up the `decryption_pending` flag.
        let effective_ids: Vec<String> = effective
            .iter()
            .map(|(id, _)| id.as_str().to_owned())
            .collect();
        // Pick the latest `asserted_at` plaintext identity among the
        // effective set. If all are pending, return None.
        let mut best: Option<MemberIdentity> = None;
        for (event_id, payload, pending) in owned.iter() {
            if *pending {
                continue;
            }
            if !effective_ids.contains(&event_id.as_str().to_owned()) {
                continue;
            }
            if let IdentityPayloadCarrier::MemberIdentity { member_identity } =
                &payload.identity_payload
            {
                // MID-5 (TODO R4): verify
                //   `member_identity.proof.payload_digest ==
                //    member_identity.canonical_payload_sha256()`
                // and that the signature covers the same canonical
                // bytes. For wire-level testing we currently surface
                // the candidate identity even when the proof has not
                // been crypto-verified. Decoders that need a hard fail
                // SHOULD gate `current_identity` behind a verified
                // flag once the signature suite lands.
                let _ = member_identity.canonical_payload_sha256();
                match &best {
                    None => best = Some(member_identity.clone()),
                    Some(current) => {
                        if member_identity.asserted_at > current.asserted_at {
                            best = Some(member_identity.clone());
                        }
                    }
                }
            }
        }
        best
    }

    /// Returns `true` when the actor has at least one
    /// `cx.member.identity.update` event but every effective event is
    /// still `decryption_pending`. Drives the "muted placeholder" UI
    /// state per MID-6.
    pub fn is_decryption_pending(&self, realm_id: &str, actor_id: &str) -> bool {
        let key = ActorKey {
            realm_id: realm_id.to_owned(),
            actor_id: actor_id.to_owned(),
        };
        let Some(stored) = self.inner.get(&key) else {
            return false;
        };
        !stored.is_empty() && stored.values().all(|event| event.decryption_pending)
    }
}

#[cfg(test)]
mod tests {
    use contrix_sdk::{
        DisplayProfile, MemberIdentity, MemberIdentityProof, MemberIdentitySignatureAlgorithm,
    };
    use serde_json::json;

    use super::*;

    fn sample_payload(actor_id: &str, name: &str) -> Value {
        json!({
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": actor_id,
            "segment": "member_identity",
            "identity_payload": {
                "member_identity": {
                    "schema": "cx.schema.member_identity.v1",
                    "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
                    "actor_id": actor_id,
                    "subject_id": actor_id,
                    "display_profile": { "display_name": name },
                    "asserted_at": "2026-05-27T12:00:00Z",
                    "proof": {
                        "verification_method": "did:web:alice.example#key-1",
                        "signature_algorithm": "Ed25519",
                        "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                        "signature": "AAAA"
                    }
                }
            }
        })
    }

    #[test]
    fn ingests_inline_event_and_resolves_current_identity() {
        let mut store = MemberIdentityStore::new();
        let actor = "did:web:alice.example";
        let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
        let event = json!({
            "event_id": "ck:event:01904100-0000-7000-8000-00000000000a",
            "kind": "cx.member.identity.update",
            "payload": sample_payload(actor, "Alice v1"),
        });
        store.ingest_inline(realm, actor, &[event]);
        let identity = store.current_identity(realm, actor).expect("resolved");
        // R3.2: `MemberIdentity` no longer carries handle fields — the
        // effective identity discloses `subject_id` + `display_profile`
        // only. Handle resolution runs §3.2.1 over the handle-claim set.
        assert_eq!(identity.subject_id.as_str(), actor);
        assert_eq!(identity.display_profile.display_name, "Alice v1");
        assert!(!store.is_decryption_pending(realm, actor));
    }

    #[test]
    fn encrypted_carrier_marks_decryption_pending() {
        let mut store = MemberIdentityStore::new();
        let actor = "did:web:alice.example";
        let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
        let event = json!({
            "event_id": "ck:event:01904100-0000-7000-8000-00000000000b",
            "kind": "cx.member.identity.update",
            "payload": {
                "realm_id": realm,
                "actor_id": actor,
                "segment": "member_identity",
                "identity_payload": {
                    "encrypted_content": {
                        "group_id": "mls:group:opaque",
                        "epoch": 7,
                        "ciphertext": "AAAA"
                    }
                }
            }
        });
        store.ingest_inline(realm, actor, &[event]);
        // MID-4: encrypted carrier without a usable MLS group state →
        // decryption_pending. The UI fallback path renders a muted
        // placeholder rather than the raw DID.
        assert!(store.current_identity(realm, actor).is_none());
        assert!(store.is_decryption_pending(realm, actor));
    }

    #[test]
    fn ignores_events_for_other_kinds() {
        let mut store = MemberIdentityStore::new();
        let actor = "did:web:alice.example";
        let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
        let event = json!({
            "event_id": "ck:event:01904100-0000-7000-8000-00000000000c",
            "kind": "cx.flow.move",
            "payload": sample_payload(actor, "Alice"),
        });
        store.ingest_inline(realm, actor, &[event]);
        assert!(store.current_identity(realm, actor).is_none());
        assert!(!store.is_decryption_pending(realm, actor));
    }

    #[test]
    fn helper_consumes_sdk_member_identity_constructor() {
        // Sanity check the SDK types compile + are reachable through
        // the wire-rename path. Yougen does not construct identities
        // itself — it consumes ingested events — but a smoke test here
        // keeps the SDK surface honest.
        let identity = MemberIdentity {
            schema: contrix_sdk::MEMBER_IDENTITY_SCHEMA.to_owned(),
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            actor_id: Did::new("did:web:alice.example".to_owned()).unwrap(),
            subject_id: Did::new("did:web:alice.example".to_owned()).unwrap(),
            display_profile: DisplayProfile {
                display_name: "Alice".to_owned(),
                avatar_blob_ref: None,
            },
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            proof: MemberIdentityProof {
                verification_method: "did:web:alice.example#key-1".to_owned(),
                signature_algorithm: MemberIdentitySignatureAlgorithm::Ed25519,
                payload_digest: contrix_sdk::Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                signature: "AAAA".to_owned(),
            },
        };
        assert!(identity.canonical_payload_sha256().is_ok());
    }
}
