//! Host conversion between the wire Welcome delivery and the provider-local
//! Welcome envelope.
//!
//! `MlsWelcomeDelivery` is the producer-signed recipient delivery object the
//! governance Station commits alongside an `ak.mls.commit`
//! (`ak:mls_welcome_delivery:<uuidv7>`); `MlsWelcomeEnvelope` is the
//! provider-local representation `garth::MlsInstallQueue` installs. Neither
//! crate owns the crossing, because closing it needs two facts only the host
//! holds:
//!
//!   * the epoch the Welcome joins at, which lives in the accepted `ak.mls.commit` payload rather
//!     than on the delivery, and
//!   * for an Agent runtime recipient, the accepted `ak.agent.key.authorize` Event that binds its
//!     verification method — the delivery carries the method alone.
//!
//! Both inputs are supplied by the caller and checked against the delivery, so
//! this never invents an endpoint identity or an epoch.

#[cfg(test)]
use arkret_models_crypto::{MlsEndpointIdentity, MlsWelcomeEnvelope};
#[cfg(test)]
use arkret_sdk::{Event, EventId, Hash, MlsCommitPayload};
use arkret_wire::MlsWelcomeDelivery;
#[cfg(test)]
use arkret_wire::MlsWelcomeRecipientEndpoint;

/// The accepted Agent-key authorization a Welcome addressed to an Agent runtime
/// binds to. Human-device recipients need none.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentRuntimeKeyBinding {
    pub(crate) agent_id: arkret_sdk::DidCoreId,
    pub(crate) verification_method: arkret_sdk::DidUrl,
    pub(crate) agent_key_authorize_event_ref: EventId,
}

/// Convert one committed Welcome delivery into the provider-local envelope that
/// `garth::MlsInstallQueue` installs.
///
/// `commit_event` MUST be the exact accepted `ak.mls.commit` the delivery names
/// in `commit_event_ref`; its `governance_binding` supplies the group id and
/// the joined epoch. An Agent runtime recipient additionally requires the
/// accepted key binding for the delivery's verification method.
#[cfg(test)]
pub(crate) fn welcome_envelope_from_delivery(
    delivery: &MlsWelcomeDelivery,
    commit_event: &Event,
    agent_key_binding: Option<&AgentRuntimeKeyBinding>,
) -> anyhow::Result<MlsWelcomeEnvelope> {
    delivery
        .validate_shape()
        .map_err(|error| anyhow::anyhow!("MLS Welcome delivery is malformed: {error}"))?;
    anyhow::ensure!(
        commit_event.kind == arkret_sdk::EventKind::MlsCommit,
        "a Welcome delivery binds an ak.mls.commit, not {}",
        commit_event.kind.as_str()
    );
    anyhow::ensure!(
        delivery.commit_event_ref == commit_event.event_id,
        "Welcome delivery {} does not bind Commit Event {}",
        delivery.welcome_id.as_str(),
        commit_event.event_id.as_str()
    );
    anyhow::ensure!(
        delivery.effective_scope == commit_event.scope_ref,
        "Welcome delivery scope differs from its Commit Event scope"
    );

    let payload: MlsCommitPayload =
        serde_json::from_value(serde_json::to_value(&commit_event.payload)?).map_err(|error| {
            anyhow::anyhow!("accepted MLS Commit payload is unreadable: {error}")
        })?;
    let binding = payload.governance_binding();
    let group_id = binding
        .mls_group_id()
        .map_err(|error| anyhow::anyhow!("MLS Commit has no group id: {error}"))?;
    anyhow::ensure!(
        binding.effective_scope() == &delivery.effective_scope,
        "MLS Commit governance binding scope differs from the Welcome delivery scope"
    );
    let recipient = endpoint_identity(delivery, agent_key_binding)?;
    let welcome = delivery.ciphertext_b64.as_str().to_owned();
    let welcome_bytes = arkret_sdk::base64url_decode(welcome.as_bytes())
        .map_err(|error| anyhow::anyhow!("Welcome ciphertext is not base64url: {error}"))?;
    let welcome_hash = Hash::new(arkret_sdk::canonical::sha256_digest(&welcome_bytes))?;

    Ok(MlsWelcomeEnvelope {
        group_id,
        epoch: binding.next_epoch(),
        recipient,
        welcome,
        welcome_hash,
        // The public ratchet tree is not carried per recipient: it is published
        // once as the group's `public_tree_ref` blob and fetched by group id and
        // epoch, so a delivery never repeats it.
        ratchet_tree: None,
    })
}

#[cfg(test)]
fn endpoint_identity(
    delivery: &MlsWelcomeDelivery,
    agent_key_binding: Option<&AgentRuntimeKeyBinding>,
) -> anyhow::Result<MlsEndpointIdentity> {
    match &delivery.recipient_endpoint {
        MlsWelcomeRecipientEndpoint::Device { device_id } => {
            let account = delivery.recipient_actor_id.as_account_id().ok_or_else(|| {
                anyhow::anyhow!("a device Welcome recipient must be an account actor")
            })?;
            Ok(MlsEndpointIdentity::human_device(
                account.principal_id.clone(),
                device_id.clone(),
            ))
        }
        MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method,
        } => {
            let binding = agent_key_binding.ok_or_else(|| {
                anyhow::anyhow!(
                    "an Agent runtime Welcome needs the accepted ak.agent.key.authorize binding \
                     for {verification_method}"
                )
            })?;
            anyhow::ensure!(
                &binding.verification_method == verification_method,
                "Agent key binding names {} but the Welcome is addressed to {verification_method}",
                binding.verification_method
            );
            anyhow::ensure!(
                delivery.recipient_actor_id.signing_principal_id().as_str()
                    == binding.agent_id.as_str(),
                "Agent key binding belongs to another Agent than the Welcome recipient"
            );
            MlsEndpointIdentity::agent_runtime(
                binding.agent_id.clone(),
                binding.verification_method.clone(),
                binding.agent_key_authorize_event_ref.clone(),
            )
            .map_err(|error| anyhow::anyhow!("Agent runtime endpoint is invalid: {error}"))
        }
    }
}

/// Queue every Welcome in one accepted MLS Commit submission that is addressed
/// to this endpoint.
///
/// `garth::retain_admissible_welcomes` decides admissibility on the wire object;
/// this converts only the deliveries it kept, so a delivery for another endpoint
/// never reaches the provider.
#[cfg(test)]
pub(crate) fn enqueue_admissible_welcomes(
    queue: &mut garth::MlsInstallQueue,
    welcomes: impl IntoIterator<Item = MlsWelcomeDelivery>,
    endpoint: &garth::LocalMlsEndpoint,
    commit_event: &Event,
    accepted_ref: &arkret_wire::CommittedEventRef,
    agent_key_binding: Option<&AgentRuntimeKeyBinding>,
) -> anyhow::Result<usize> {
    let admissible = garth::retain_admissible_welcomes(welcomes, endpoint, &commit_event.event_id);
    let mut queued = 0;
    for delivery in admissible {
        let envelope = welcome_envelope_from_delivery(&delivery, commit_event, agent_key_binding)?;
        queue
            .enqueue(garth::QueuedMlsInstall {
                accepted_ref: accepted_ref.clone(),
                artifact: garth::AcceptedMlsArtifact::Welcome(envelope),
            })
            .map_err(|error| anyhow::anyhow!("queue accepted MLS Welcome: {error}"))?;
        queued += 1;
    }
    Ok(queued)
}

/// Every producer-signed Welcome delivery this device has journalled but not
/// consumed yet.
///
/// The durable to-device inbox is a weakly typed journal, so the only sound
/// test for "this row is a Welcome" is that its `content` parses closed into
/// `MlsWelcomeDelivery` and passes the delivery's own shape validation. A
/// Welcome is not an Event and carries no Event kind, so there is nothing else
/// to match on.
pub(crate) fn welcome_from_inbox_row(message: &serde_json::Value) -> Option<MlsWelcomeDelivery> {
    let value = if message
        .get("delivery_kind")
        .and_then(serde_json::Value::as_str)
        == Some("mls_welcome")
    {
        message.get("mls_welcome")?
    } else {
        message.get("content")?
    };
    serde_json::from_value::<MlsWelcomeDelivery>(value.clone())
        .ok()
        .filter(|delivery| delivery.validate_shape().is_ok())
}

pub(crate) fn pending_welcome_deliveries(
    messages: &[serde_json::Value],
) -> Vec<MlsWelcomeDelivery> {
    messages.iter().filter_map(welcome_from_inbox_row).collect()
}

/// The pending Welcome deliveries that belong to one Realm.
pub(crate) fn welcome_deliveries_for_realm(
    messages: &[serde_json::Value],
    realm_id: &str,
) -> Vec<MlsWelcomeDelivery> {
    pending_welcome_deliveries(messages)
        .into_iter()
        .filter(|delivery| delivery.realm_id.as_str() == realm_id.trim())
        .collect()
}

/// A stable dedup hint over the Welcome deliveries pending for one Realm.
///
/// UI effects fold this into their `seen` key so a Welcome that arrives after
/// an earlier empty probe re-triggers the join drain. The hint is derived from
/// the delivery ids, which are unique and immutable
/// (`ak:mls_welcome_delivery:<uuidv7>`), so it changes exactly when the set of
/// pending Welcomes changes.
pub(crate) fn local_mls_welcome_hint_for_realm(
    messages: &[serde_json::Value],
    realm_id: &str,
) -> String {
    let mut ids = welcome_deliveries_for_realm(messages, realm_id)
        .into_iter()
        .map(|delivery| delivery.welcome_id.as_str().to_owned())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    format!("{}:{}", ids.len(), ids.join(","))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        DetachedObjectSignature, DetachedSignatureAlgorithm, DetachedSignatureContext,
        KeypackageClaimId, MlsWelcomeDeliveryId,
    };

    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const DEVICE: &str = "ak:device:0196419b-0000-7000-8000-000000000001";

    fn realm_id() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new(REALM).unwrap()
    }

    fn scope() -> arkret_sdk::ScopeRef {
        arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        }
    }

    fn actor() -> arkret_sdk::ActorId {
        arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    fn producer_proof() -> DetachedObjectSignature {
        DetachedObjectSignature {
            context: DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#device").unwrap(),
            signed_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            created_at: "2026-09-16T00:00:00.000Z".parse().unwrap(),
            sig: arkret_wire::Base64UrlString::new(arkret_sdk::base64url_encode([7_u8; 64]))
                .unwrap(),
        }
    }

    /// One accepted `ak.mls.commit` that advances the Realm scope to epoch 4.
    fn commit_event() -> Event {
        let binding = arkret_sdk::MlsGovernanceBindingPayload::realm(
            realm_id(),
            Some(EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [9; 32],
            )),
            3,
            4,
            0,
        )
        .unwrap();
        let commit_bytes = [1_u8, 2, 3, 4];
        let envelope = arkret_sdk::MlsCommitEnvelope {
            group_id: binding.mls_group_id().unwrap(),
            epoch: 4,
            commit: arkret_sdk::base64url_encode(commit_bytes),
            commit_digest: Hash::new(arkret_sdk::canonical::sha256_digest(commit_bytes)).unwrap(),
            ratchet_tree: None,
        };
        let payload = arkret_sdk::MlsCommitPayload::new(
            EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [9; 32]),
            0,
            &envelope,
            binding,
        )
        .unwrap();
        arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::MlsCommit>::new(
            scope(),
            actor(),
            payload,
        )
        .unwrap()
        .author_with_digest_suite(
            "2026-09-16T00:00:00.000Z".parse().unwrap(),
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap()
        .into_event()
    }

    fn delivery(commit: &Event) -> MlsWelcomeDelivery {
        MlsWelcomeDelivery {
            welcome_id: MlsWelcomeDeliveryId::new(
                "ak:mls_welcome_delivery:0196419b-0000-7000-8000-00000000000a",
            )
            .unwrap(),
            realm_id: realm_id(),
            effective_scope: scope(),
            commit_event_ref: commit.event_id.clone(),
            recipient_actor_id: actor(),
            recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
                device_id: arkret_sdk::DeviceId::new(DEVICE).unwrap(),
            },
            keypackage_claim_ref: KeypackageClaimId::new(
                "ak:keypackage_claim:0196419b-0000-7000-8000-00000000000b",
            )
            .unwrap(),
            ciphertext_b64: arkret_wire::Base64UrlString::new(arkret_sdk::base64url_encode(
                [5_u8; 48],
            ))
            .unwrap(),
            producer_proof: producer_proof(),
        }
    }

    #[test]
    fn a_device_delivery_becomes_the_provider_envelope_at_the_commit_epoch() {
        let commit = commit_event();
        let envelope = welcome_envelope_from_delivery(&delivery(&commit), &commit, None).unwrap();

        assert_eq!(
            envelope.group_id,
            garth::mls::mls_group_id_for_scope(&scope()).unwrap()
        );
        // The epoch comes from the Commit, never from the delivery: a Welcome
        // delivery carries no epoch of its own.
        assert_eq!(envelope.epoch, 4);
        assert_eq!(
            envelope.recipient,
            MlsEndpointIdentity::human_device(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_sdk::DeviceId::new(DEVICE).unwrap(),
            )
        );
        assert_eq!(
            envelope.welcome_hash,
            Hash::new(arkret_sdk::canonical::sha256_digest([5_u8; 48])).unwrap()
        );
        assert!(envelope.ratchet_tree.is_none());
    }

    #[test]
    fn a_delivery_that_names_another_commit_is_refused() {
        let commit = commit_event();
        let mut wrong = delivery(&commit);
        wrong.commit_event_ref = EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [3; 32]);
        let error = welcome_envelope_from_delivery(&wrong, &commit, None).unwrap_err();
        assert!(
            error.to_string().contains("does not bind Commit Event"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn an_agent_runtime_delivery_needs_its_accepted_key_binding() {
        let commit = commit_event();
        let mut agent = delivery(&commit);
        agent.recipient_endpoint = MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#runtime").unwrap(),
        };
        let error = welcome_envelope_from_delivery(&agent, &commit, None).unwrap_err();
        assert!(
            error.to_string().contains("ak.agent.key.authorize"),
            "unexpected error: {error}"
        );

        let binding = AgentRuntimeKeyBinding {
            agent_id: arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#runtime").unwrap(),
            agent_key_authorize_event_ref: EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [4; 32],
            ),
        };
        let envelope = welcome_envelope_from_delivery(&agent, &commit, Some(&binding)).unwrap();
        assert!(matches!(
            envelope.recipient,
            MlsEndpointIdentity::AgentRuntime { .. }
        ));
    }

    #[test]
    fn a_delivery_for_another_endpoint_is_never_queued() {
        let commit = commit_event();
        let endpoint = garth::LocalMlsEndpoint {
            realm_id: realm_id(),
            actor_id: actor(),
            endpoint: MlsWelcomeRecipientEndpoint::Device {
                device_id: arkret_sdk::DeviceId::new(
                    "ak:device:0196419b-0000-7000-8000-0000000000ff",
                )
                .unwrap(),
            },
        };
        let accepted_ref = arkret_wire::CommittedEventRef {
            event_id: commit.event_id.clone(),
            commit_id: arkret_sdk::RealmCommitId::from_digest([2; 32]),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id(),
            },
            stream_position: 7,
        };
        let mut queue = garth::MlsInstallQueue::default();
        let queued = enqueue_admissible_welcomes(
            &mut queue,
            [delivery(&commit)],
            &endpoint,
            &commit,
            &accepted_ref,
            None,
        )
        .unwrap();
        assert_eq!(queued, 0);
        assert_eq!(queue.pending().count(), 0);
    }

    /// One durable to-device inbox row carrying `delivery` as its content.
    fn inbox_row(delivery: &MlsWelcomeDelivery) -> serde_json::Value {
        serde_json::json!({
            "message_id": delivery.welcome_id.as_str(),
            "content": serde_json::to_value(delivery).unwrap(),
        })
    }

    #[test]
    fn only_rows_that_parse_as_a_closed_delivery_are_pending_welcomes() {
        let commit = commit_event();
        let delivery = delivery(&commit);
        let mut malformed = inbox_row(&delivery);
        malformed["content"]["effective_scope"] = serde_json::json!({ "kind": "realm_genesis" });
        let messages = vec![
            serde_json::json!({ "message_id": "m1", "content": { "kind": "read_receipt" } }),
            inbox_row(&delivery),
            // A delivery whose scope fails `validate_shape` is never admitted.
            malformed,
        ];
        let pending = pending_welcome_deliveries(&messages);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].welcome_id, delivery.welcome_id);
    }

    #[test]
    fn signed_welcome_branch_is_journalled_without_device_message_wrapping() {
        let delivery = delivery(&commit_event());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("welcome-journal.json");
        let mut writer = crate::state::LocalStateStore::with_path(path.clone());
        let branch = arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome {
            mls_welcome: delivery.clone(),
        };
        assert_eq!(
            writer
                .ingest_recipient_deliveries(std::slice::from_ref(&branch))
                .unwrap(),
            1
        );
        assert_eq!(writer.ingest_recipient_deliveries(&[branch]).unwrap(), 0);
        let reopened = crate::state::LocalStateStore::with_path(path);
        let inbox = reopened.to_device_inbox();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0]["delivery_kind"], "mls_welcome");
        assert!(inbox[0].get("content").is_none());
        assert_eq!(
            pending_welcome_deliveries(&inbox)[0].welcome_id,
            delivery.welcome_id
        );
    }

    #[test]
    fn the_welcome_hint_changes_only_when_the_pending_set_changes() {
        let commit = commit_event();
        let delivery = delivery(&commit);
        let empty = local_mls_welcome_hint_for_realm(&[], REALM);
        let one = local_mls_welcome_hint_for_realm(&[inbox_row(&delivery)], REALM);
        assert_ne!(empty, one);
        // A repeated journal row is the same Welcome, so the hint is stable.
        assert_eq!(
            one,
            local_mls_welcome_hint_for_realm(&[inbox_row(&delivery), inbox_row(&delivery)], REALM)
        );
        // A Welcome for another Realm never leaks into this Realm's hint.
        assert_eq!(
            empty,
            local_mls_welcome_hint_for_realm(
                &[inbox_row(&delivery)],
                "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN"
            )
        );
        assert_eq!(
            welcome_deliveries_for_realm(&[inbox_row(&delivery)], REALM).len(),
            1
        );
    }
}
