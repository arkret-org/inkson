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

// Integration tests exercise the admitted product boundary using its existing
// host carriers, without exposing a second decoder or a verification bypass.
#[cfg(feature = "spec-conformance")]
pub use crate::runtime::projection::AdmittedSignal;
#[cfg(feature = "spec-conformance")]
pub use crate::state::ClientLocalState;

/// Upper bound on retained read positions. Each entry is one
/// `(realm, strand, actor)` triple, so this only bites in a very large Realm
/// with a very long session; the least recently updated entry is dropped first.
const MAX_READ_POSITIONS: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ReadPositionKey {
    realm_id: String,
    /// `read_scope.object_ref` — the Strand for a `kind="strand"` receipt.
    scope_ref: String,
    actor_id: arkret_sdk::ActorId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReadPosition {
    /// `ak:message:<event-token>` — the receipt's full `event_id` retyped, so the chat
    /// timeline can compare it to `protocol_message_id` directly.
    message_id: String,
    payload_sequence: u64,
    target_author: arkret_sdk::ActorId,
    /// Insertion order counter, used only for bounded eviction.
    stored_at: u64,
}

#[derive(Debug, Default)]
struct ReadReceiptProjection {
    positions: BTreeMap<(arkret_sdk::ActorId, ReadPositionKey), ReadPosition>,
    stored_counter: u64,
    generation: Option<(arkret_sdk::ActorId, u64)>,
}

impl ReadReceiptProjection {
    /// Fold one authenticated receipt in. Returns `true` when the stored set
    /// changed.
    fn apply(
        &mut self,
        key: ReadPositionKey,
        message_id: String,
        payload_sequence: u64,
        viewer: arkret_sdk::ActorId,
        target_author: arkret_sdk::ActorId,
    ) -> bool {
        let key = (viewer, key);
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
                target_author,
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

    fn readers_of(
        &self,
        realm_id: &str,
        scope_ref: &str,
        message_id: &str,
        viewer: &arkret_sdk::ActorId,
        target_author: &arkret_sdk::ActorId,
    ) -> Vec<arkret_sdk::ActorId> {
        self.positions
            .iter()
            .filter(|((owner, key), position)| {
                owner == viewer
                    && key.realm_id == realm_id
                    && key.scope_ref == scope_ref
                    && position.message_id == message_id
                    && &position.target_author == target_author
            })
            .map(|((_, key), _)| key.actor_id.clone())
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
    /// `policy` is the exact scope's accepted `ak.scope.read_receipt_policy`.
    /// `read-receipts.md` §2.5 puts the `disclosure="disabled"` and
    /// `visibility="private"` enforcement point on the **client**: a Sync
    /// Service cannot read a receipt at all, so a compliant receiver is what
    /// makes those two settings observable. An unauthorized receipt is dropped
    /// here rather than rendered.
    pub fn apply_authorized(
        &mut self,
        signal: &crate::runtime::projection::AdmittedSignal,
        policy: &arkret_sdk::ReadReceiptPolicy,
        local_actor: &arkret_sdk::ActorId,
        state: &crate::state::ClientLocalState,
    ) -> bool {
        // The typed closed profile the receiver already selected. No
        // field-name parse: `signal.md` §1.1 forbids it, and a receipt that did
        // not validate against `ak.schema.read_receipt.v1` never gets here.
        let arkret_sdk::SignalPlaintext::ReadReceipt(receipt) = &signal.payload else {
            return false;
        };
        let Some((key, message_id)) = strand_read_position(signal, receipt) else {
            return false;
        };
        // Only a verified accepted MessageCreate can establish the target's
        // author. The signed scope and exact Strand/track must also agree;
        // neither a cached sender label nor the receipt's reader is evidence.
        let Some(target) = state.verified_message_commits.iter().find(|target| {
            target.accepted_ref.event_id == receipt.event_id
                && target.scope_ref == *signal.scope_ref()
                && target.strand_id.as_str() == key.scope_ref
                && receipt
                    .read_scope
                    .track
                    .as_deref()
                    .is_none_or(|track| track == target.track_name)
        }) else {
            return false;
        };
        if !read_receipt_is_displayable(policy, local_actor, &target.actor_id) {
            return false;
        }
        self.retain_generation(
            Some(local_actor),
            state.current_generation,
            state.current_reset_required,
        );
        self.projection.write().apply(
            key,
            message_id,
            receipt.payload_sequence,
            local_actor.clone(),
            target.actor_id.clone(),
        )
    }

    /// A new account/current cut never revives hints retained at an older cut.
    pub(crate) fn retain_generation(
        &mut self,
        viewer: Option<&arkret_sdk::ActorId>,
        generation: u64,
        reset: bool,
    ) {
        let next = viewer.map(|viewer| (viewer.clone(), generation));
        let changed = self.projection.peek().generation != next;
        if changed || (reset && !self.projection.peek().positions.is_empty()) {
            let mut projection = self.projection.write();
            projection.positions.clear();
            projection.generation = next;
        }
    }

    fn retract_target(&mut self, realm: &str, strand: &str, message: Option<&str>) {
        let remove = |key: &ReadPositionKey, position: &ReadPosition| {
            key.realm_id == realm
                && key.scope_ref == strand
                && message.is_none_or(|message| position.message_id == message)
        };
        if self
            .projection
            .peek()
            .positions
            .iter()
            .any(|((_, key), position)| remove(key, position))
        {
            self.projection
                .write()
                .positions
                .retain(|(_, key), position| !remove(key, position));
        }
    }

    /// Actors whose read position lands exactly on `message_id`.
    ///
    /// `read-receipts.md` §2.2 makes a receipt causal — everything before the
    /// named position is read too — but the avatar row deliberately renders on
    /// the *latest* message each actor reported, which is what a reader expects
    /// to see and what keeps one receipt from decorating a whole timeline.
    pub fn readers_of(
        &self,
        realm_id: &str,
        strand_id: &str,
        message_id: &str,
        viewer: &arkret_sdk::ActorId,
        target_author: &arkret_sdk::ActorId,
    ) -> Vec<arkret_sdk::ActorId> {
        self.projection
            .read()
            .readers_of(realm_id, strand_id, message_id, viewer, target_author)
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
/// - `disclosure="disabled"`: the scope generates no receipts, so an arriving one is non-compliant.
///   Rendering it would leak a read position the scope said would not exist.
/// - `visibility="private"`: only the full ActorId of the target Message's author may observe the
///   receipt; its reader is a different identity.
fn read_receipt_is_displayable(
    policy: &arkret_sdk::ReadReceiptPolicy,
    local_actor: &arkret_sdk::ActorId,
    target_author: &arkret_sdk::ActorId,
) -> bool {
    policy.disclosure != arkret_sdk::ReadReceiptDisclosure::Disabled
        && (policy.visibility != arkret_sdk::ReadReceiptVisibility::Private
            || target_author == local_actor)
}

/// The Strand read position one decrypted receipt names, or `None` when it does
/// not name one.
fn strand_read_position(
    signal: &crate::runtime::projection::AdmittedSignal,
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
    // the Message id, which is the same full Event identity retyped. Doing that conversion
    // through the SDK keeps the retyping rule in one place instead of letting
    // this view rewrite an id prefix by hand.
    Some((
        ReadPositionKey {
            realm_id: signal.scope_ref().realm_id().as_str().to_owned(),
            scope_ref: scope_ref.to_owned(),
            actor_id: receipt.actor_id.clone(),
        },
        arkret_sdk::MessageId::from_event_id(&receipt.event_id)
            .as_str()
            .to_owned(),
    ))
}

/// The timeline's receipt row. Both the current viewer and locally visible
/// Message author must still match the evidence accepted with the receipt.
#[component]
pub fn ReadReceiptIndicator(
    realm_id: String,
    strand_id: String,
    message_id: Option<String>,
    target_author: Option<arkret_sdk::ActorId>,
    viewer: arkret_sdk::ActorId,
    display: bool,
    policy: Option<arkret_sdk::ReadReceiptPolicy>,
) -> Element {
    let hub = ReadReceiptHub::try_use();
    let allowed = display
        && target_author.as_ref().is_some_and(|author| {
            policy
                .as_ref()
                .is_some_and(|policy| read_receipt_is_displayable(policy, &viewer, author))
        });
    let retract_realm = realm_id.clone();
    let retract_strand = strand_id.clone();
    let retract_message = message_id.clone();
    use_effect(use_reactive(
        (&allowed, &retract_realm, &retract_strand, &retract_message),
        move |(allowed, realm, strand, message)| {
            if !allowed && let Some(mut hub) = hub {
                hub.retract_target(&realm, &strand, message.as_deref());
            }
        },
    ));
    let readers = match (ReadReceiptHub::try_use(), message_id, target_author, policy) {
        (Some(hub), Some(message), Some(author), Some(policy))
            if display && read_receipt_is_displayable(&policy, &viewer, &author) =>
        {
            hub.readers_of(&realm_id, &strand_id, &message, &viewer, &author)
        }
        _ => Vec::new(),
    };
    if readers.is_empty() {
        return rsx! {};
    }
    let attr = serde_json::to_string(&readers).unwrap_or_default();
    rsx! {
        div {
            class: "read-receipt-indicator",
            "data-testid": "read-receipt-indicator",
            "data-readers": "{attr}",
            for actor in &readers {
                crate::components::IdentityAvatar {
                    seed: actor.signing_principal_id().to_string(),
                    alt_text: actor.to_string(),
                    class: "read-receipt-avatar avatar-img".to_owned(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor(principal: &str, station: &str) -> arkret_sdk::ActorId {
        arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            format!("ak:did_core:web:{principal}").parse().unwrap(),
            format!("ak:did_core:web:{station}").parse().unwrap(),
        ))
    }

    fn key(reader: arkret_sdk::ActorId) -> ReadPositionKey {
        ReadPositionKey {
            realm_id: "realm".to_owned(),
            scope_ref: "strand".to_owned(),
            actor_id: reader,
        }
    }

    #[test]
    fn reordered_receipts_do_not_move_a_position_backwards() {
        let mut projection = ReadReceiptProjection::default();
        let reader = actor("reader", "station-a");
        let author = actor("author", "station-a");
        assert!(projection.apply(
            key(reader.clone()),
            "latest".to_owned(),
            7,
            author.clone(),
            author.clone()
        ));
        for sequence in [6, 7] {
            assert!(!projection.apply(
                key(reader.clone()),
                "older".to_owned(),
                sequence,
                author.clone(),
                author.clone()
            ));
        }
        assert_eq!(
            projection.readers_of("realm", "strand", "latest", &author, &author),
            vec![reader]
        );
        assert!(
            projection
                .readers_of("realm", "strand", "older", &author, &author)
                .is_empty()
        );
    }

    #[test]
    fn reader_accounts_at_different_stations_have_distinct_positions() {
        let mut projection = ReadReceiptProjection::default();
        let author = actor("author", "station-a");
        let first = actor("reader", "station-a");
        let second = actor("reader", "station-b");
        for reader in [&first, &second] {
            assert!(projection.apply(
                key(reader.clone()),
                "message".to_owned(),
                1,
                author.clone(),
                author.clone()
            ));
        }
        assert_eq!(
            projection.readers_of("realm", "strand", "message", &author, &author),
            vec![first, second]
        );
        for (realm, strand) in [("other", "strand"), ("realm", "other")] {
            assert!(
                projection
                    .readers_of(realm, strand, "message", &author, &author)
                    .is_empty()
            );
        }
        assert!(
            projection
                .readers_of(
                    "realm",
                    "strand",
                    "message",
                    &actor("author", "station-b"),
                    &author
                )
                .is_empty()
        );
        assert!(
            projection
                .readers_of(
                    "realm",
                    "strand",
                    "message",
                    &author,
                    &actor("other", "station-a")
                )
                .is_empty()
        );
    }

    #[test]
    fn projection_remains_bounded_and_evicts_oldest_position() {
        let mut projection = ReadReceiptProjection::default();
        let author = actor("author", "station-a");
        for index in 0..MAX_READ_POSITIONS + 5 {
            projection.apply(
                key(actor(&format!("reader{index}"), "station-a")),
                "message".to_owned(),
                1,
                author.clone(),
                author.clone(),
            );
        }
        assert_eq!(projection.positions.len(), MAX_READ_POSITIONS);
        assert!(
            !projection
                .positions
                .contains_key(&(author.clone(), key(actor("reader0", "station-a"))))
        );
    }
    #[test]
    fn receipt_positions_do_not_share_sequence_state_between_local_accounts() {
        let mut projection = ReadReceiptProjection::default();
        let reader = actor("reader", "station-a");
        let author = actor("author", "station-a");
        let other_account = actor("author", "station-b");
        for viewer in [&author, &other_account] {
            assert!(projection.apply(
                key(reader.clone()),
                "message".to_owned(),
                7,
                viewer.clone(),
                author.clone()
            ));
            assert_eq!(
                projection.readers_of("realm", "strand", "message", viewer, &author),
                vec![reader.clone()]
            );
        }
    }
}
