//! Receiver-side projection of other members' `ak.receipt.read` Signals.
//!
//! `read-receipts.md` §1.1 splits the two mechanisms deliberately: the Signal
//! `ak.receipt.read` is the *shared* "someone else has read up to here" hint,
//! while `ak.read_cursor.advance` is this actor's own private multi-device
//! cursor. Only the first one belongs here.
//!
//! Everything is memory-only. A receipt is a UI hint with no durable Event and
//! no delivery guarantee, so persisting it would invent state the protocol does
//! not keep. It is *not* TTL-expired either: the envelope TTL bounds how fresh a
//! receipt must be to be **accepted** (`signal.md` §2), not how long the derived
//! read position stays true. Dropping the avatar 30 seconds after a peer read a
//! message would be wrong, and re-deriving it would need a receipt the peer has
//! no reason to resend.
//!
//! Ordering is by the plaintext `payload_sequence`, which `read-receipts.md`
//! §2.3 requires to be monotonic per `(realm_id, read_scope, actor)` — the same
//! key this projection stores under, so the sender-side debounce/merge and the
//! receiver-side merge agree.

use std::collections::BTreeMap;

use dioxus::prelude::*;

/// Upper bound on retained read positions. Each entry is one
/// `(realm, strand, actor)` triple, so this only bites in a very large Realm
/// with a very long session; the least recently updated entry is dropped first.
const MAX_READ_POSITIONS: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ReadPositionKey {
    realm_id: String,
    /// `read_scope.object_ref` — the Strand for a `kind="strand"` receipt.
    scope_ref: String,
    actor_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReadPosition {
    /// `ak:message:<uuidv7>` — the receipt's `event_id` retyped, so the chat
    /// timeline can compare it to `protocol_message_id` directly.
    message_id: String,
    payload_sequence: u64,
    /// Insertion order counter, used only for bounded eviction.
    stored_at: u64,
}

#[derive(Debug, Default)]
struct ReadReceiptProjection {
    positions: BTreeMap<ReadPositionKey, ReadPosition>,
    stored_counter: u64,
}

impl ReadReceiptProjection {
    /// Fold one authenticated receipt in. Returns `true` when the stored set
    /// changed.
    fn apply(&mut self, key: ReadPositionKey, message_id: String, payload_sequence: u64) -> bool {
        if let Some(existing) = self.positions.get(&key)
            && existing.payload_sequence >= payload_sequence
        {
            // A reordered or duplicated receipt must never move a peer's read
            // position backwards.
            return false;
        }
        self.stored_counter = self.stored_counter.saturating_add(1);
        self.positions.insert(
            key,
            ReadPosition {
                message_id,
                payload_sequence,
                stored_at: self.stored_counter,
            },
        );
        while self.positions.len() > MAX_READ_POSITIONS {
            let Some(oldest) = self
                .positions
                .iter()
                .min_by_key(|(_, position)| position.stored_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.positions.remove(&oldest);
        }
        true
    }

    fn readers_of(&self, realm_id: &str, scope_ref: &str, message_id: &str) -> Vec<String> {
        self.positions
            .iter()
            .filter(|(key, position)| {
                key.realm_id == realm_id
                    && key.scope_ref == scope_ref
                    && position.message_id == message_id
            })
            .map(|(key, _)| key.actor_id.clone())
            .collect()
    }
}

/// App-tree handle to the read-receipt projection.
#[derive(Clone, Copy)]
pub struct ReadReceiptHub {
    projection: Signal<ReadReceiptProjection>,
}

impl ReadReceiptHub {
    pub fn new() -> Self {
        Self {
            projection: Signal::new(ReadReceiptProjection::default()),
        }
    }

    pub fn try_use() -> Option<Self> {
        try_consume_context::<Self>()
    }

    /// Apply one decrypted `ak.receipt.read` plaintext.
    ///
    /// The caller has already had the envelope admitted by
    /// [`garth::SignalReceiver`], so the sending device is authenticated and
    /// `plaintext.actor_id` equals the authenticated `sender_actor_id`.
    ///
    /// Only `kind="strand"` receipts are projected: they are the only ones the
    /// message timeline can render, and a Realm/thread/view-scoped receipt
    /// pointing at a different surface must not be silently re-attributed to a
    /// Strand.
    ///
    /// `policy` is the Realm's accepted `ak.realm.read_receipt_policy`.
    /// `read-receipts.md` §2.5 puts the `disclosure="disabled"` and
    /// `visibility="private"` enforcement point on the **client**: a Sync
    /// Service cannot read a receipt at all, so a compliant receiver is what
    /// makes those two settings observable. An unauthorized receipt is dropped
    /// here rather than rendered.
    pub fn apply_authorized(
        &mut self,
        plaintext: &garth::SignalPlaintext,
        policy: &arkret_sdk::ReadReceiptPolicy,
        local_actor_id: &str,
    ) -> bool {
        // The typed closed profile, selected by `kind` in the SDK dispatch. No
        // field-name parse: `signal.md` §1.1 forbids it, and a receipt that did
        // not validate against `ak.schema.read_receipt.v1` never gets here.
        let Some(receipt) = plaintext.read_receipt() else {
            return false;
        };
        if !read_receipt_is_displayable(receipt, policy, local_actor_id) {
            return false;
        }
        let Some((key, message_id)) = strand_read_position(plaintext, receipt) else {
            return false;
        };
        self.projection
            .write()
            .apply(key, message_id, receipt.payload_sequence)
    }

    /// Actors whose read position lands exactly on `message_id`.
    ///
    /// `read-receipts.md` §2.2 makes a receipt causal — everything before the
    /// named position is read too — but the avatar row deliberately renders on
    /// the *latest* message each actor reported, which is what a reader expects
    /// to see and what keeps one receipt from decorating a whole timeline.
    pub fn readers_of(&self, realm_id: &str, strand_id: &str, message_id: &str) -> Vec<String> {
        self.projection
            .read()
            .readers_of(realm_id, strand_id, message_id)
    }
}

impl Default for ReadReceiptHub {
    fn default() -> Self {
        Self::new()
    }
}

/// `read-receipts.md` §2.5 — may this receipt be shown to the local user?
///
/// Both rules are client-side by construction: the receipt travels as Signal
/// plaintext inside the ciphertext, so no service can apply them.
///
/// - `disclosure="disabled"`: the Realm generates no receipts, so an arriving one is non-compliant.
///   Rendering it would leak a read position the Realm said would not exist.
/// - `visibility="private"`: a receipt is only for the actor who authored the read *target*'s
///   audience of one — the reader themself. Everyone else drops it.
fn read_receipt_is_displayable(
    receipt: &arkret_sdk::ReadReceipt,
    policy: &arkret_sdk::ReadReceiptPolicy,
    local_actor_id: &str,
) -> bool {
    if policy.disclosure == arkret_sdk::ReadReceiptDisclosure::Disabled {
        return false;
    }
    if policy.visibility == arkret_sdk::ReadReceiptVisibility::Private
        && receipt.actor_id.as_str() != local_actor_id
    {
        return false;
    }
    true
}

/// The Strand read position one decrypted receipt names, or `None` when it does
/// not name one.
fn strand_read_position(
    plaintext: &garth::SignalPlaintext,
    receipt: &arkret_sdk::ReadReceipt,
) -> Option<(ReadPositionKey, String)> {
    if receipt.read_scope.kind != arkret_sdk::ReadScopeKind::Strand {
        return None;
    }
    let scope_ref = receipt
        .read_scope
        .object_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    // The receipt names the Event id it read up to; the timeline is keyed by
    // the Message id, which is the same UUIDv7 retyped. Doing that conversion
    // through the SDK keeps the retyping rule in one place instead of letting
    // this view rewrite an id prefix by hand.
    Some((
        ReadPositionKey {
            realm_id: plaintext.scope_ref.realm_id().as_str().to_owned(),
            scope_ref: scope_ref.to_owned(),
            actor_id: receipt.actor_id.as_str().to_owned(),
        },
        arkret_sdk::MessageId::from_event_id(&receipt.event_id)
            .as_str()
            .to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-00000000000a";
    const MESSAGE_ID: &str = "ak:message:01904100-0000-7000-8000-00000000000a";

    fn key(actor: &str) -> ReadPositionKey {
        ReadPositionKey {
            realm_id: "ak:realm:r".to_owned(),
            scope_ref: "ak:strand:s".to_owned(),
            actor_id: actor.to_owned(),
        }
    }

    #[test]
    fn a_reordered_receipt_does_not_move_a_read_position_backwards() {
        let mut projection = ReadReceiptProjection::default();
        assert!(projection.apply(key("did:web:a"), "ak:message:m2".to_owned(), 7));
        assert!(!projection.apply(key("did:web:a"), "ak:message:m1".to_owned(), 6));
        assert_eq!(
            projection.readers_of("ak:realm:r", "ak:strand:s", "ak:message:m2"),
            vec!["did:web:a".to_owned()]
        );
        assert!(
            projection
                .readers_of("ak:realm:r", "ak:strand:s", "ak:message:m1")
                .is_empty()
        );
    }

    #[test]
    fn readers_are_scoped_to_the_realm_and_strand() {
        let mut projection = ReadReceiptProjection::default();
        projection.apply(key("did:web:a"), "ak:message:m2".to_owned(), 1);
        projection.apply(
            ReadPositionKey {
                realm_id: "ak:realm:other".to_owned(),
                scope_ref: "ak:strand:s".to_owned(),
                actor_id: "did:web:b".to_owned(),
            },
            "ak:message:m2".to_owned(),
            1,
        );
        assert_eq!(
            projection.readers_of("ak:realm:r", "ak:strand:s", "ak:message:m2"),
            vec!["did:web:a".to_owned()]
        );
    }

    #[test]
    fn the_projection_stays_bounded_by_dropping_the_oldest_position() {
        let mut projection = ReadReceiptProjection::default();
        for index in 0..(MAX_READ_POSITIONS + 5) {
            projection.apply(
                key(&format!("did:web:a{index}")),
                "ak:message:m2".to_owned(),
                1,
            );
        }
        assert_eq!(projection.positions.len(), MAX_READ_POSITIONS);
        assert!(!projection.positions.contains_key(&key("did:web:a0")));
    }

    fn receipt(body: serde_json::Value) -> garth::SignalPlaintext {
        let serde_json::Value::Object(body) = body else {
            unreachable!("test body must be an object");
        };
        let at = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        garth::SignalPlaintext {
            kind: "ak.receipt.read".to_owned(),
            actor_id: arkret_sdk::Did::new("did:web:a").unwrap(),
            payload_sequence: 3,
            ttl_ms: None,
            body: body.into_iter().collect(),
            sent_at: at,
            expires_at: at + chrono::Duration::seconds(30),
            scope_ref: arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001")
                    .unwrap(),
            },
            seal_ref: arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))
                .unwrap(),
            sender_device_id: arkret_sdk::DeviceId::new(
                "ak:device:01904100-0000-7000-8000-000000000002",
            )
            .unwrap(),
        }
    }

    /// A Realm-scoped receipt carries no Strand and a thread receipt points at a
    /// root message; neither may be re-attributed to a Strand timeline. A
    /// `strand` scope without `object_ref` is malformed and equally unusable.
    #[test]
    fn only_strand_scoped_receipts_have_a_timeline_to_land_on() {
        for scope in [
            json!({"kind": "realm"}),
            json!({"kind": "thread", "object_ref": "ak:message:m"}),
            json!({"kind": "strand"}),
            json!({"kind": "strand", "object_ref": "  "}),
        ] {
            let plaintext = receipt(json!({
                "kind": "ak.receipt.read",
                "read_scope": scope,
                "event_id": EVENT_ID,
            }));
            assert!(strand_read_position(&plaintext).is_none());
        }

        let strand = "ak:strand:01904100-0000-7000-8000-00000000000b";
        let plaintext = receipt(json!({
            "kind": "ak.receipt.read",
            "read_scope": {"kind": "strand", "object_ref": strand, "track_name": "discussion"},
            "event_id": EVENT_ID,
        }));
        let (key, message_id) = strand_read_position(&plaintext).expect("strand receipt");
        assert_eq!(key.scope_ref, strand);
        assert_eq!(key.actor_id, "did:web:a");
        assert_eq!(
            key.realm_id,
            "ak:realm:01904100-0000-7000-8000-000000000001"
        );
        // The receipt names an Event id; the timeline is keyed by the same
        // UUIDv7 retyped as a Message id.
        assert_eq!(message_id, MESSAGE_ID);
    }
}
