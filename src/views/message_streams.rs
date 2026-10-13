//! UI bridge for transient `ak.message.stream` generation previews.

use dioxus::prelude::*;

#[derive(Clone, Copy)]
pub struct MessageStreamHub {
    projection: Signal<garth::MessageStreamProjection>,
    admitted: Signal<Vec<crate::runtime::projection::AdmittedSignal>>,
}

impl MessageStreamHub {
    pub fn new() -> Self {
        Self {
            projection: Signal::new(garth::MessageStreamProjection::new()),
            admitted: Signal::new(Vec::new()),
        }
    }

    pub fn try_use() -> Option<Self> {
        try_consume_context::<Self>()
    }

    /// Applies a frame only after the receiver has admitted the Signal
    /// (envelope, producer proof, AEAD, sequence) and the sink has authorized
    /// both `ak.message.stream.send` and `ak.message.create` for the verified
    /// sender in this scope.
    pub fn apply_admitted(
        &mut self,
        signal: &crate::runtime::projection::AdmittedSignal,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> garth::Result<garth::MessageStreamApplyOutcome> {
        let outcome = self.projection.write().apply_plaintext(
            &signal.domain,
            &signal.payload,
            &|domain: &garth::SignalSequenceDomain, frame: &arkret_models_collaboration::signal_message_stream::MessageStreamFrame| {
                signal
                    .product_authority
                    .as_deref()
                    .is_some_and(|authority| {
                        signal.expires_at > observed_at
                            && authority.authority_commit_id == signal.authority_commit_id
                            && authority.parent_realm_authority_commit_id
                                == signal.parent_realm_authority_commit_id
                            && arkret_policy::signal_authorization::message_stream_allowed(
                                authority,
                                &domain.sender_actor_id,
                                &domain.scope_ref,
                                frame.strand_id(),
                                observed_at,
                            )
                    })
            },
            observed_at,
        )?;
        if matches!(
            outcome,
            garth::MessageStreamApplyOutcome::Activated | garth::MessageStreamApplyOutcome::Updated
        ) {
            let mut retained = self.admitted.write();
            retained.retain(|old| !same_preview(old, signal));
            retained.push(signal.clone());
        }
        self.prune_admitted();
        Ok(outcome)
    }

    fn prune_admitted(&mut self) {
        let projection = self.projection.read();
        self.admitted.write().retain(|signal| {
            projection
                .previews()
                .any(|preview| signal_matches_preview(signal, preview))
        });
    }

    pub fn retained(&self) -> Vec<crate::runtime::projection::AdmittedSignal> {
        self.admitted.read().clone()
    }

    pub fn retain_eligible(&mut self, eligible: &[crate::runtime::projection::AdmittedSignal]) {
        self.projection.write().retain_previews(|preview| {
            eligible
                .iter()
                .any(|signal| signal_matches_preview(signal, preview))
        });
        self.prune_admitted();
    }

    /// Removes a preview only after the durable Event and its verified sender
    /// endpoint have passed the normal schema, proof, authorization and reducer gates.
    pub fn bind_verified_final(
        &mut self,
        event: &arkret_sdk::Event,
        verified_sender_endpoint: &arkret_sdk::SignalSequenceEndpoint,
    ) -> garth::Result<Option<garth::MessageStreamPreview>> {
        self.projection
            .write()
            .bind_committed_final(event, verified_sender_endpoint)
    }

    pub fn maintain(&mut self, now: chrono::DateTime<chrono::Utc>) {
        let mut projection = self.projection.write();
        projection.mark_stalled(now);
        projection.expire(now);
        drop(projection);
        self.prune_admitted();
    }

    pub fn visible_for(&self, realm_id: &str, strand_id: &str) -> Vec<MessageStreamCard> {
        self.projection
            .read()
            .previews()
            .filter(|preview| {
                preview.scope_ref.realm_id().as_str() == realm_id
                    && preview.strand_id.as_str() == strand_id
                    && matches!(
                        preview.status,
                        garth::MessageStreamPreviewStatus::Active
                            | garth::MessageStreamPreviewStatus::Stalled
                    )
            })
            .map(MessageStreamCard::from)
            .collect()
    }
}

impl Default for MessageStreamHub {
    fn default() -> Self {
        Self::new()
    }
}

fn same_preview(
    left: &crate::runtime::projection::AdmittedSignal,
    right: &crate::runtime::projection::AdmittedSignal,
) -> bool {
    match (&left.payload, &right.payload) {
        (
            arkret_sdk::SignalPlaintext::MessageStream(left_frame),
            arkret_sdk::SignalPlaintext::MessageStream(right_frame),
        ) => left.domain == right.domain && left_frame.message_id() == right_frame.message_id(),
        _ => false,
    }
}

fn signal_matches_preview(
    signal: &crate::runtime::projection::AdmittedSignal,
    preview: &garth::MessageStreamPreview,
) -> bool {
    matches!(&signal.payload, arkret_sdk::SignalPlaintext::MessageStream(frame) if frame.message_id() == &preview.message_id)
        && signal.domain.sender_actor_id == preview.sender_actor_id
        && signal.domain.endpoint == preview.sender_endpoint
        && signal.domain.scope_ref == preview.scope_ref
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageStreamCard {
    pub sender_actor_id: String,
    pub message_id: String,
    pub text: String,
    pub truncated: bool,
    pub stalled: bool,
}

impl From<&garth::MessageStreamPreview> for MessageStreamCard {
    fn from(preview: &garth::MessageStreamPreview) -> Self {
        Self {
            sender_actor_id: preview
                .sender_actor_id
                .signing_principal_id()
                .as_str()
                .to_owned(),
            message_id: preview.message_id.as_str().to_owned(),
            text: preview.text.clone(),
            truncated: preview.truncated,
            stalled: preview.status == garth::MessageStreamPreviewStatus::Stalled,
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{
        AccountId, ActorId, CapabilityActionId, CommitStreamHead, CommitStreamRef, MessageId,
        MessageStreamFormat, MessageStreamId, MessageStreamKeyframe, RealmCommitId, ScopeRef,
        SignalPlaintext, SignalProductAuthority,
    };

    use super::*;
    use crate::runtime::projection::AdmittedSignal;
    #[test]
    fn mounted_hub_requires_both_live_actions_before_body_side_effects() {
        let realm: arkret_sdk::RealmId = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
            .parse()
            .unwrap();
        let strand: arkret_sdk::StrandId = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv"
            .parse()
            .unwrap();
        let actor = ActorId::account(AccountId::new(
            "ak:did_core:web:alice.example".parse().unwrap(),
            "ak:did_core:web:station-a.example".parse().unwrap(),
        ));
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let now: chrono::DateTime<chrono::Utc> = "2026-10-13T15:00:00.000Z".parse().unwrap();
        let event =
            arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [7; 32]);
        let grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant = serde_json::from_value(serde_json::json!({
            "id":arkret_sdk::GrantId::from_event_id(&event), "schema":"ak.schema.capability.v1", "realm_id":realm,
            "issuer_id":actor, "subject":actor, "actions":[CapabilityActionId::MESSAGE_STREAM_SEND,CapabilityActionId::MESSAGE_CREATE],
            "resources":[{"kind":"strand","realm_id":realm,"strand_id":strand}], "status":"active", "issued_at":"2026-10-01T00:00:00.000Z",
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":event,"authority_generation":0}],
            "authority_root_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":event,"authority_generation":0}], "authority_depth":1
        })).unwrap();
        let head = CommitStreamHead {
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            commit_id: RealmCommitId::from_digest([9; 32]),
            stream_position: 9,
        };
        let material = SignalProductAuthority {
            authority_commit_id: head.commit_id.clone(),
            parent_realm_authority_commit_id: None,
            current_realm_head: head.clone(),
            current_scope_head: head.clone(),
            sent_at: now,
            grants: vec![grant.clone()],
            current_grants: vec![grant],
            historical_product_policies: vec![],
            current_product_policies: vec![],
            owner_actions: vec![],
            profile_actions: vec![],
            agent: None,
        };
        let mut admitted = AdmittedSignal {
            domain: arkret_sdk::SignalSequenceDomain {
                sender_actor_id: actor,
                endpoint: arkret_sdk::SignalSequenceEndpoint::AccountDevice {
                    device_id: arkret_sdk::DeviceId::new_v7_at(1_790_000_000_000),
                },
                scope_ref: scope,
            },
            signer_verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#device-1")
                .unwrap(),
            product_authority: None,
            authority_commit_id: head.commit_id,
            parent_realm_authority_commit_id: None,
            payload: SignalPlaintext::MessageStream(arkret_sdk::MessageStreamFrame::Keyframe(
                MessageStreamKeyframe::new(
                    0,
                    strand.clone(),
                    MessageId::from_event_id(&event),
                    0,
                    MessageStreamId::new_v7_at(1_790_000_000_000),
                    0,
                    MessageStreamFormat::Plain,
                    "private preview body",
                    false,
                )
                .unwrap(),
            )),
            expires_at: now + chrono::Duration::seconds(30),
        };
        let mut dom = VirtualDom::new(|| rsx! {});
        dom.rebuild_in_place();
        dom.in_scope(ScopeId::ROOT, || {
            let mut hub = MessageStreamHub::new();
            assert!(hub.apply_admitted(&admitted, now).is_err());
            assert!(hub.visible_for(realm.as_str(), strand.as_str()).is_empty());
            let mut missing = material.clone();
            missing.grants[0].actions.pop();
            admitted.product_authority = Some(Box::new(missing));
            assert!(hub.apply_admitted(&admitted, now).is_err());
            assert!(hub.visible_for(realm.as_str(), strand.as_str()).is_empty());
            let mut revoked = material.clone();
            revoked.current_grants.clear();
            admitted.product_authority = Some(Box::new(revoked));
            assert!(hub.apply_admitted(&admitted, now).is_err());
            assert!(hub.visible_for(realm.as_str(), strand.as_str()).is_empty());
            admitted.product_authority = Some(Box::new(material));
            assert!(hub.apply_admitted(&admitted, now).is_ok());
            assert_eq!(
                hub.visible_for(realm.as_str(), strand.as_str())[0].text,
                "private preview body"
            );
            assert_eq!(hub.retained().len(), 1);
            hub.retain_eligible(&[]);
            assert!(hub.retained().is_empty());
            assert!(hub.visible_for(realm.as_str(), strand.as_str()).is_empty());
        });
    }
}
