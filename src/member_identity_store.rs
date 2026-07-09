//! R3.2 — Realm-scoped `ck.member.identity.update` event store.
//!
//! Spec source: arkret-spec @ b56cab1 (2026-05-28)
//! `models/member-identity.md` + `artifacts/schemas/member-identity.schema.json`.
//!
//! Sync ingest pipeline (MID-2): when a `members[]` roster entry on an
//! `account.subscribe` frame inlines `identity_events[]` (or references
//! events that already arrived via `state.events`), the renderer copies
//! the raw envelopes into [`MemberIdentityStore`] keyed by
//! `(realm_id, actor_id, segment)`. The effective set is computed via
//! the SDK's [`arkret_sdk::effective_identity_events`] helper (MID-3).
//!
//! MID-4 (MLS decryption) is still a carrier-level concern (an encrypted
//! carrier surfaces as `decryption_pending`). MID-5 (proof signature
//! verification) is implemented: [`MemberIdentityStore::current_identity`]
//! fail-closed verifies each plaintext candidate's `proof` before it can
//! become the effective identity — (a) `proof.payload_digest` MUST equal the
//! recomputed `canonical_payload_sha256()`, and (b) the raw signature MUST
//! verify under the asserter's authoritative device signing key resolved
//! through [`crate::device_directory`] (never taken from the envelope). A
//! candidate that fails either check is dropped from the effective plaintext
//! set, mirroring the Welcome `claim_envelope` directory-resolution +
//! fail-closed pattern in `mls/runtime/message.rs`. Handle now comes from the
//! `ck.schema.handle_claim.v1` set via §3.2.1 primary handle selection —
//! `MemberIdentity` no longer carries `primary_handle` / `handles[]`.

use std::collections::BTreeMap;

use arkret_sdk::{
    Did, EventId, IdentityPayloadCarrier, MemberIdentity, MemberIdentityProof,
    MemberIdentitySegment, MemberIdentitySignatureAlgorithm, MemberIdentityUpdatePayload, RealmId,
    effective_identity_events,
};
use serde_json::Value;

/// Per-actor key on the store. `(realm_id, actor_id)` — the segment
/// (`member_identity`) is implicit at v1.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActorKey {
    pub realm_id: String,
    pub actor_id: String,
}

/// Stored `ck.member.identity.update` event record. Carries the parsed
/// SDK payload + the raw envelope (so we can re-hash it for replacement
/// edge verification). `decryption_pending` is set when the carrier was
/// an `encrypted_content` envelope we couldn't decrypt yet (missing MLS epoch).
#[derive(Clone, Debug)]
pub struct StoredIdentityEvent {
    pub event_id: String,
    pub payload: MemberIdentityUpdatePayload,
    pub decryption_pending: bool,
}

/// Per-(realm, actor) collection of `ck.member.identity.update` event
/// records. Keyed by event id; insertion is idempotent.
#[derive(Clone, Debug, Default)]
pub struct MemberIdentityStore {
    inner: BTreeMap<ActorKey, BTreeMap<String, StoredIdentityEvent>>,
}

impl MemberIdentityStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// MID-2 — record a `ck.member.identity.update` event for a given
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
    /// `kind == "ck.member.identity.update"`, and a `payload` body that
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
            if kind != "ck.member.identity.update" {
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
                // MID-5: fail-closed proof verification. A candidate whose proof
                // does not (a) bind `payload_digest` to the recomputed canonical
                // digest AND (b) verify under the asserter's authoritative
                // directory key is dropped — it MUST NOT become the effective
                // plaintext identity. This prevents a malicious / compromised
                // sync peer from forging any actor's `subject_id` /
                // `display_profile`.
                if !verify_member_identity_proof(member_identity) {
                    continue;
                }
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
    /// `ck.member.identity.update` event but every effective event is
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

/// MID-5 — fail-closed verification of a plaintext [`MemberIdentity`] proof.
///
/// Returns `true` ONLY when both hold:
///   (a) `proof.payload_digest` byte-equals the recomputed
///       `canonical_payload_sha256()` (the signed bytes are the bytes shown);
///   (b) the raw `proof.signature` verifies under the asserter's authoritative
///       device signing key, resolved through [`crate::device_directory`] (the
///       same cache the Welcome / realm-key-share receive paths use) — never a
///       key taken from the envelope itself.
///
/// Resolution + trust rules (mirrors `verify_welcome_claim_envelope_signer`):
///   - `proof.verification_method` is a `did:method:identifier#device` URL; its controller DID MUST
///     equal the identity's `actor_id` (an actor can only assert its own member identity).
///   - the fragment selects the asserting device; its key is looked up in the device-directory
///     cache. A directory NegativeHit (revoked / absent) or a Miss (not resolved) is fail-closed
///     (rejected). Only `Ed25519` is verifiable on this synchronous path; `ES256` / `ES384` are
///     rejected (no synchronous verifier wired) rather than silently trusted.
fn verify_member_identity_proof(identity: &MemberIdentity) -> bool {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let proof: &MemberIdentityProof = &identity.proof;

    // (a) digest binding: the proof MUST commit to the exact canonical bytes.
    let Ok(recomputed) = identity.canonical_payload_sha256() else {
        return false;
    };
    if proof.payload_digest.as_str() != recomputed {
        return false;
    }

    // Only Ed25519 is verifiable synchronously. ECDSA suites are fail-closed.
    if !matches!(
        proof.signature_algorithm,
        MemberIdentitySignatureAlgorithm::Ed25519
    ) {
        return false;
    }

    // The verification_method controller MUST be the asserting actor.
    let actor_id = identity.actor_id.as_str();
    let (controller, fragment) = match proof.verification_method.split_once('#') {
        Some((controller, fragment)) => (
            controller
                .split_once('?')
                .map_or(controller, |(head, _)| head),
            fragment,
        ),
        // No fragment → no device selector → cannot resolve an authoritative
        // key → fail-closed.
        None => return false,
    };
    if controller != actor_id {
        return false;
    }
    let device_id = fragment.trim();
    if device_id.is_empty() {
        return false;
    }

    // Resolve the asserter's authoritative device signing key (sync, cache-only;
    // primed by the sync engine's member-identity prefetch). Miss / NegativeHit
    // are fail-closed.
    let verifying_key =
        match crate::device_directory::cached_device_signing_key(actor_id, device_id) {
            crate::device_directory::CacheLookup::Hit(material) => {
                let Ok(bytes) = material.ed25519_bytes() else {
                    return false;
                };
                let Ok(key) = VerifyingKey::from_bytes(&bytes) else {
                    return false;
                };
                key
            }
            crate::device_directory::CacheLookup::NegativeHit
            | crate::device_directory::CacheLookup::Miss => return false,
        };

    // (b) signature over the canonical payload bytes (the same bytes the digest
    // commits to).
    let Ok(signing_bytes) = identity.canonical_payload_bytes() else {
        return false;
    };
    let Ok(sig_bytes) = arkret_sdk::base64url_decode(proof.signature.as_bytes()) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    verifying_key.verify(&signing_bytes, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use arkret_sdk::DisplayProfile;
    use arkret_sdk::signatures::PublicKeyMaterial;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;

    use super::*;

    const TEST_REALM: &str = "ak:realm:01904100-0000-7000-8000-000000000001";
    const TEST_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000d001";

    /// Build a `ck.member.identity.update` payload whose `member_identity`
    /// proof is a real Ed25519 signature over the canonical payload bytes,
    /// signed by `signer`. `verification_method` selects `actor#device`.
    fn signed_payload(actor_id: &str, device_id: &str, name: &str, signer: &SigningKey) -> Value {
        let mut identity = MemberIdentity {
            schema: arkret_sdk::MEMBER_IDENTITY_SCHEMA.to_owned(),
            realm_id: RealmId::new(TEST_REALM).unwrap(),
            actor_id: Did::new(actor_id.to_owned()).unwrap(),
            subject_id: Did::new(actor_id.to_owned()).unwrap(),
            display_profile: DisplayProfile {
                display_name: name.to_owned(),
                avatar_blob_ref: None,
            },
            asserted_at: chrono::DateTime::parse_from_rfc3339("2026-05-27T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            expires_at: None,
            proof: MemberIdentityProof {
                verification_method: format!("{actor_id}#{device_id}"),
                signature_algorithm: MemberIdentitySignatureAlgorithm::Ed25519,
                payload_digest: arkret_sdk::Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                signature: String::new(),
            },
        };
        let canonical_bytes = identity.canonical_payload_bytes().unwrap();
        let digest = identity.canonical_payload_sha256().unwrap();
        identity.proof.payload_digest = arkret_sdk::Hash::new(digest).unwrap();
        let signature = signer.sign(&canonical_bytes);
        identity.proof.signature = arkret_sdk::base64url_encode(&signature.to_bytes());
        json!({
            "realm_id": TEST_REALM,
            "actor_id": actor_id,
            "segment": "member_identity",
            "identity_payload": { "member_identity": identity },
        })
    }

    /// Seed the device directory with `signer`'s verifying key for
    /// `(actor, device)` so the synchronous MID-5 verifier can resolve it.
    fn seed_directory(actor: &str, device: &str, signer: &SigningKey) {
        let bytes = signer.verifying_key().to_bytes().to_vec();
        crate::device_directory::seed_positive_for_test(
            actor,
            device,
            PublicKeyMaterial::Ed25519Raw { bytes },
        );
    }

    #[test]
    fn ingests_inline_event_and_resolves_current_identity() {
        let mut store = MemberIdentityStore::new();
        let actor = "did:web:alice.example";
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        seed_directory(actor, TEST_DEVICE, &signer);
        let event = json!({
            "event_id": "ak:event:01904100-0000-7000-8000-00000000000a",
            "kind": "ck.member.identity.update",
            "payload": signed_payload(actor, TEST_DEVICE, "Alice v1", &signer),
        });
        store.ingest_inline(TEST_REALM, actor, &[event]);
        // MID-5: a directory-resolved, correctly-signed proof verifies and the
        // effective identity is surfaced.
        let identity = store.current_identity(TEST_REALM, actor).expect("resolved");
        assert_eq!(identity.subject_id.as_str(), actor);
        assert_eq!(identity.display_profile.display_name, "Alice v1");
        assert!(!store.is_decryption_pending(TEST_REALM, actor));
        crate::device_directory::invalidate(actor, TEST_DEVICE);
    }

    #[test]
    fn rejects_forged_identity_with_unverifiable_proof() {
        // MID-5 fail-closed: an attacker forges a member_identity (correct
        // digest binding) but signs it with a key NOT in the directory for the
        // claimed actor. The verifier MUST drop it — `current_identity` returns
        // None rather than surfacing the forged subject / display name.
        let mut store = MemberIdentityStore::new();
        let actor = "did:web:victim.example";
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        // Directory holds the victim's REAL key, not the attacker's.
        let real = SigningKey::from_bytes(&[1u8; 32]);
        seed_directory(actor, TEST_DEVICE, &real);
        let event = json!({
            "event_id": "ak:event:01904100-0000-7000-8000-00000000000d",
            "kind": "ck.member.identity.update",
            "payload": signed_payload(actor, TEST_DEVICE, "Impersonator", &attacker),
        });
        store.ingest_inline(TEST_REALM, actor, &[event]);
        assert!(
            store.current_identity(TEST_REALM, actor).is_none(),
            "forged identity must not be surfaced"
        );
        crate::device_directory::invalidate(actor, TEST_DEVICE);
    }

    #[test]
    fn rejects_identity_when_directory_key_absent() {
        // MID-5 fail-closed: a correctly self-signed identity whose device key
        // is NOT cached (directory Miss) MUST NOT resolve — the key is never
        // taken from the envelope.
        let mut store = MemberIdentityStore::new();
        let actor = "did:web:nobody.example";
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        let event = json!({
            "event_id": "ak:event:01904100-0000-7000-8000-00000000000e",
            "kind": "ck.member.identity.update",
            "payload": signed_payload(actor, TEST_DEVICE, "Unresolved", &signer),
        });
        store.ingest_inline(TEST_REALM, actor, &[event]);
        assert!(store.current_identity(TEST_REALM, actor).is_none());
    }

    #[test]
    fn encrypted_carrier_marks_decryption_pending() {
        let mut store = MemberIdentityStore::new();
        let actor = "did:web:alice.example";
        let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
        let event = json!({
            "event_id": "ak:event:01904100-0000-7000-8000-00000000000b",
            "kind": "ck.member.identity.update",
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
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let event = json!({
            "event_id": "ak:event:01904100-0000-7000-8000-00000000000c",
            "kind": "ck.strand.move",
            "payload": signed_payload(actor, TEST_DEVICE, "Alice", &signer),
        });
        store.ingest_inline(TEST_REALM, actor, &[event]);
        assert!(store.current_identity(TEST_REALM, actor).is_none());
        assert!(!store.is_decryption_pending(TEST_REALM, actor));
    }

    #[test]
    fn helper_consumes_sdk_member_identity_constructor() {
        // Sanity check the SDK types compile + are reachable through
        // the wire-rename path. Inkson does not construct identities
        // itself — it consumes ingested events — but a smoke test here
        // keeps the SDK surface honest.
        let identity = MemberIdentity {
            schema: arkret_sdk::MEMBER_IDENTITY_SCHEMA.to_owned(),
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
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
                payload_digest: arkret_sdk::Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                signature: "AAAA".to_owned(),
            },
        };
        assert!(identity.canonical_payload_sha256().is_ok());
    }
}
