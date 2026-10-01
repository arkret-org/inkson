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
    /// This Strand is the controller-private Agent Sidecar surface. Kept on
    /// the channel projection so every rendered message can carry an explicit
    /// privacy badge in the hosted source-Strand shell.
    pub(crate) is_private_sidecar: bool,
    /// Explicit Strand security state from Strand metadata. `None` inherits
    /// the current Realm / Space security posture.
    pub(crate) security_encrypted: Option<bool>,
    /// P3B.2.3 / P3B.2.4 — Circle scope this Strand was
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
    /// `ak:circle:…`
    pub(crate) circle_id: String,
    /// Circle title used in the banner heading + accent-rail tooltip.
    pub(crate) title: String,
    /// Cached member count for the banner subline. `0` means the
    /// projection has not been hydrated yet — render "members" with
    /// no count rather than `0 members`.
    pub(crate) member_count: u32,
}

impl ChannelEntity {
    pub(crate) fn effective_scope(&self, realm_id: &str) -> Option<arkret_sdk::ScopeRef> {
        let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?;
        match self.scope_circle.as_ref() {
            Some(circle) => Some(arkret_sdk::ScopeRef::Circle {
                realm_id,
                circle_id: arkret_sdk::CircleId::new(circle.circle_id.clone()).ok()?,
            }),
            None => Some(arkret_sdk::ScopeRef::Realm { realm_id }),
        }
    }
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
    /// The producer is not a human device and its signer evidence has not
    /// been verified yet. The row stays visible but flagged.
    NeedsVerification,
}

impl MessageCryptoState {
    pub(crate) fn is_pending(&self) -> bool {
        matches!(self, Self::Decrypting | Self::KeyMissing)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChatMessage {
    /// Scope fixed by the local ordinary composer before authoring. Private
    /// Sidecar rows never acquire this ordinary-timeline provenance.
    pub(crate) local_scope: Option<arkret_sdk::ScopeRef>,
    pub(crate) realm_id: String,
    pub(crate) id: String,
    pub(crate) protocol_message_id: Option<String>,
    /// Signed membership actor, kept separately from the principal display label.
    pub(crate) actor_id: Option<arkret_sdk::ActorId>,
    pub(crate) sender: String,
    /// §4.10 — envelope-level `executed_by`. Present only for
    /// act-on-behalf events: `sender` (actor_id) is the controller and
    /// `executed_by` is the agent that performed the action. Drives the
    /// "X via Y" double-signature attribution. `None` for ordinary and
    /// reply-as-agent messages.
    pub(crate) executed_by: Option<String>,
    pub(crate) body: String,
    /// Protocol-declared text format. `None` is a safe literal-text fallback
    /// for remote Content Blocks that omit the SHOULD-level discriminator.
    pub(crate) content_format: Option<arkret_sdk::TextFormat>,
    pub(crate) timestamp: String,
    pub(crate) created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) strand_id: String,
    pub(crate) reply_to: Option<String>,
    pub(crate) reactions: Vec<(String, Vec<String>)>,
    pub(crate) redacted: bool,
    pub(crate) edited: bool,
    pub(crate) revisions: Vec<String>,
    /// Event digests of every currently observed maximal revision branch.
    /// A subsequent edit covers this complete observed frontier; more than one
    /// ref also drives the ordinary-branch conflict affordance in the UI.
    /// Exact source of the current message-revision causal-register winner.
    pub(crate) revision_source: Option<arkret_sdk::Hash>,
    pub(crate) pending: bool,
    pub(crate) failed: bool,
    pub(crate) error: Option<String>,
    pub(crate) mentions: Vec<MentionNode>,
    /// T7.4: E2EE decrypt status for this message. Defaults to
    /// `Plaintext`; messages with `content.encrypted_content` start at
    /// `Decrypting` until the audit-emitter future resolves them.
    pub(crate) crypto_state: MessageCryptoState,
}

impl ChatMessage {
    pub(crate) fn matches_id_or_protocol(&self, message_ref: &str) -> bool {
        self.id == message_ref
            || self
                .protocol_message_id
                .as_deref()
                .is_some_and(|protocol_id| protocol_id == message_ref)
    }

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

    pub(crate) fn is_newer_or_same_lifecycle_version_than(&self, existing: &Self) -> bool {
        match (existing.created_at.as_ref(), self.created_at.as_ref()) {
            (Some(existing_at), Some(incoming_at)) if incoming_at != existing_at => {
                incoming_at > existing_at
            }
            (Some(_), Some(_)) => self.id.as_str() >= existing.id.as_str(),
            (Some(_), None) => false,
            (None, Some(_)) => true,
            (None, None) => true,
        }
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
    Member,
}

impl SpaceParticipantRole {
    pub(crate) fn label(self) -> &'static str {
        "Member"
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentParticipantMetadata {
    pub(crate) controller_principal_id: String,
    pub(crate) controller_handle: String,
    pub(crate) agent_slug: String,
    pub(crate) display_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SpaceParticipant {
    /// Full membership identity; absent only for display-only agent metadata.
    pub(crate) actor_id: Option<arkret_sdk::ActorId>,
    pub(crate) principal_id: arkret_sdk::DidCoreId,
    pub(crate) display_name: Option<String>,
    pub(crate) handle_label: Option<String>,
    pub(crate) display_name_rank: u8,
    pub(crate) role: SpaceParticipantRole,
    pub(crate) is_self: bool,
    /// `true` when selector mention metadata identifies this principal as an agent.
    /// Surfaces a 🤖 badge in member lists,
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

impl SpaceParticipant {
    pub(crate) fn roster_key(&self) -> String {
        self.actor_id
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("display-principal:{}", self.principal_id))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ParticipantRosterRow {
    Participant(SpaceParticipant),
    ControllerWithAgents {
        controller: SpaceParticipant,
        agents: Vec<SpaceParticipant>,
    },
}

/// Receiver-side proof verdict for a committed chat Event
/// (`server-trusted-results.md` §2, fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChatProofVerdict {
    /// Non-persistent system row with no attributed actor. Persistent actor
    /// messages without proofs are rejected before projection.
    Unattributed,
    /// Human-device producer proof is self-consistent, or an Agent producer
    /// verified against its historical signer evidence.
    Verified,
    /// Proof present but not self-consistent, or Agent evidence failed. The
    /// message MUST be dropped (fail-closed).
    Rejected,
    /// Proof is self-consistent but the producer is not a human device and its
    /// Agent signer evidence is not available yet. The message is shown
    /// flagged (`NeedsVerification`) rather than trusted.
    Unresolved,
}
