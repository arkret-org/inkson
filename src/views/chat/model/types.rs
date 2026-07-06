use super::*;

pub(crate) const CHAT_EMOJI_GRID: &[&str] = &[
    "\u{1f44d}",
    "\u{2764}\u{fe0f}",
    "\u{1f389}",
    "\u{1f440}",
    "\u{1f680}",
];

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChannelEntity {
    pub(crate) strand_id: String,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) category: String,
    pub(crate) topic: Option<String>,
    pub(crate) unread: usize,
    pub(crate) is_default: bool,
    /// Explicit Strand security state from Strand metadata. `None` inherits
    /// the current Realm / Space security posture.
    pub(crate) security_encrypted: Option<bool>,
    /// CKP-0007 P3B.2.3 / P3B.2.4 — Circle scope this Strand was
    /// created under, when the Strand projection carries a
    /// `scope_circle_id`. The composer banner and the per-message
    /// accent rail read from this field; `None` means the Strand
    /// inherits the parent Realm scope and no banner / rail is
    /// rendered.
    pub(crate) scope_circle: Option<StrandScopeCircle>,
}

/// Minimal Circle-scope projection embedded on each [`ChannelEntity`].
/// Mirrors the subset of [`crate::circle::CircleSummary`] needed by
/// the chat composer banner and message accent rail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StrandScopeCircle {
    /// `ck:circle:…`
    pub(crate) circle_id: String,
    /// Circle title used in the banner heading + accent-rail tooltip.
    pub(crate) title: String,
    /// Cached member count for the banner subline. `0` means the
    /// projection has not been hydrated yet — render "members" with
    /// no count rather than `0 members`.
    pub(crate) member_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SharedPinScopeKind {
    Realm,
    Strand,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedPinScope {
    pub(crate) kind: SharedPinScopeKind,
    pub(crate) id: String,
}

impl SharedPinScope {
    pub(crate) fn realm(id: impl Into<String>) -> Self {
        Self {
            kind: SharedPinScopeKind::Realm,
            id: id.into(),
        }
    }

    pub(crate) fn strand(id: impl Into<String>) -> Self {
        Self {
            kind: SharedPinScopeKind::Strand,
            id: id.into(),
        }
    }

    pub(crate) fn from_wire(kind: &str, id: &str) -> Option<Self> {
        match kind {
            "realm" => Some(Self::realm(id.to_owned())),
            "strand" => Some(Self::strand(id.to_owned())),
            _ => None,
        }
    }
}

/// T7.4: end-to-end encryption decryption state for a message.
///
/// Derived from the presence of `content.encrypted_content` on the
/// envelope plus what the local MLS group can currently do with it.
/// `Plaintext` is the default; encrypted messages cycle
/// `Decrypting -> (Plaintext | KeyMissing | NeedsVerification)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MessageCryptoState {
    /// Body is already plaintext (no `encrypted_content`).
    Plaintext,
    /// We see an `encrypted_content` envelope and the MLS group exists, but a
    /// decrypt round-trip hasn't completed for this event yet.
    Decrypting,
    /// `encrypted_content` present, but the local device cannot decrypt it:
    /// Welcome may be pending, the epoch may be outside the current snapshot,
    /// or the shared-history key share has not arrived.
    KeyMissing,
    /// Sender device hasn't been verified (cross-signing missing or
    /// fingerprint mismatch). The body still decrypted, but we flag it.
    NeedsVerification,
    /// A late-recovery transition was attempted, but the required membership,
    /// key-share-source, or expiry/retention guard rejected it.
    LateRecoveryRejected,
}

impl MessageCryptoState {
    pub(crate) fn is_pending(&self) -> bool {
        matches!(self, Self::Decrypting | Self::KeyMissing)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChatMessage {
    pub(crate) realm_id: String,
    pub(crate) id: String,
    pub(crate) protocol_message_id: Option<String>,
    pub(crate) sender: String,
    /// CKP-0008 §4.10 — envelope-level `executed_by`. Present only for
    /// act-on-behalf events: `sender` (actor_id) is the controller and
    /// `executed_by` is the agent that performed the action. Drives the
    /// "X via Y" double-signature attribution. `None` for ordinary and
    /// reply-as-agent messages.
    pub(crate) executed_by: Option<String>,
    pub(crate) body: String,
    pub(crate) timestamp: String,
    pub(crate) strand_id: String,
    pub(crate) reply_to: Option<String>,
    pub(crate) reactions: Vec<(String, Vec<String>)>,
    pub(crate) redacted: bool,
    pub(crate) edited: bool,
    pub(crate) revisions: Vec<String>,
    pub(crate) pending: bool,
    pub(crate) failed: bool,
    pub(crate) error: Option<String>,
    pub(crate) mentions: Vec<MentionNode>,
    /// T7.4: E2EE decrypt status for this message. Defaults to
    /// `Plaintext`; messages with `content.encrypted_content` start at
    /// `Decrypting` until the audit-emitter future resolves them.
    pub(crate) crypto_state: MessageCryptoState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModerationAppealPrompt {
    pub(crate) realm_id: String,
    pub(crate) decision_ref: String,
    pub(crate) target_ref: String,
    pub(crate) state: String,
    pub(crate) verdict: Option<String>,
}

impl ChatMessage {
    pub(crate) fn pin_saved_target_ref(&self) -> &str {
        self.protocol_message_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(self.id.as_str())
    }

    pub(crate) fn reply_target_ref(&self) -> Option<&str> {
        self.protocol_message_id
            .as_deref()
            .map(str::trim)
            .filter(|value| is_schema_message_id(value))
            .or_else(|| {
                let id = self.id.trim();
                is_schema_message_id(id).then_some(id)
            })
    }

    pub(crate) fn mutation_target_ref(&self) -> &str {
        self.protocol_message_id
            .as_deref()
            .map(str::trim)
            .filter(|value| is_schema_message_id(value))
            .unwrap_or(self.id.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedMessagePin {
    pub(crate) pin_scope_kind: SharedPinScopeKind,
    pub(crate) pin_scope_id: String,
    pub(crate) target_ref: String,
    pub(crate) rank: String,
}

impl SharedMessagePin {
    pub(crate) fn new(pin_scope: &SharedPinScope, target_ref: String, rank: String) -> Self {
        Self {
            pin_scope_kind: pin_scope.kind,
            pin_scope_id: pin_scope.id.clone(),
            target_ref,
            rank,
        }
    }

    pub(crate) fn matches_scope(&self, pin_scope: &SharedPinScope) -> bool {
        self.pin_scope_kind == pin_scope.kind && self.pin_scope_id == pin_scope.id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiscussionSidePanel {
    Users,
    Settings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SpaceParticipantRole {
    Owner,
    Admin,
    Member,
}

impl SpaceParticipantRole {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Owner => "Owner",
            Self::Admin => "Admin",
            Self::Member => "Member",
        }
    }

    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::Owner => 0,
            Self::Admin => 1,
            Self::Member => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentParticipantMetadata {
    pub(crate) controller_did: String,
    pub(crate) controller_handle: String,
    pub(crate) agent_slug: String,
    pub(crate) display_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SpaceParticipant {
    pub(crate) did: String,
    pub(crate) display_name: Option<String>,
    pub(crate) handle_label: Option<String>,
    pub(crate) display_name_rank: u8,
    pub(crate) role: SpaceParticipantRole,
    pub(crate) is_self: bool,
    /// `true` when this DID was registered as an agent endpoint
    /// (`ck.agent.endpoint`). Surfaces a 🤖 badge in member lists,
    /// @mention picker rows, and chat sender attribution so operators
    /// can immediately distinguish bot/agent principals from real
    /// human members.
    pub(crate) is_agent: bool,
    pub(crate) agent_metadata: Option<AgentParticipantMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MentionInlinePart {
    pub(crate) text: String,
    pub(crate) mention_label: Option<String>,
    pub(crate) is_local: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ParticipantRosterRow {
    Participant(SpaceParticipant),
    ControllerWithAgents {
        controller: SpaceParticipant,
        agents: Vec<SpaceParticipant>,
    },
}

/// Receiver-side proof verdict for a persistent chat message envelope
/// (`device-lifecycle.md` §8.2, fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChatProofVerdict {
    /// No `proofs` carried on this projection — nothing to verify here. Existing
    /// (legacy / proofless) projections keep their prior behavior; the device
    /// signature gate only applies once envelopes carry `proofs`.
    NotApplicable,
    /// Sender proof verified against the authoritative directory verify key.
    Verified,
    /// Proof present but verification failed, or the device is revoked / absent
    /// from the directory. The message MUST be dropped (fail-closed).
    Rejected,
    /// Proof present but the sender's verify key is not yet in the directory
    /// cache. The message is shown flagged (`NeedsVerification`) rather than
    /// trusted; a directory prefetch makes a later render resolve it.
    Unresolved,
}
