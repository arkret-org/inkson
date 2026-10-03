//! Single authoritative source for cross-module test fixtures.
//!
//! Before this module every test file re-derived the same identifiers from the
//! same literals: roughly twenty near-identical `test_authority` / `device_id`
//! / `realm_id` helpers, several of them subtly different (one accepted only
//! the `ak:did_core:` form, one projected a `did:` first). A wire-shape change
//! therefore had twenty landing sites and no single place to fix.
//!
//! Constructors here take the widest input each identifier accepts and panic on
//! a malformed fixture, because a fixture that cannot be built is a broken test
//! rather than a runtime condition worth propagating.

/// Station used by fixtures that do not care which Station issued the account.
/// Matches the literal the per-module helpers agreed on before unification.
pub(crate) const STATION_ID: &str = "ak:did_core:web:principal.example";

/// Station used by the fixtures that model a remote server rather than the
/// local principal Station.
pub(crate) const SERVER_STATION_ID: &str = "ak:did_core:web:server.example";

/// Core id from either a stable `ak:did_core:` id or a resolvable `did:` URI.
pub(crate) fn core_id(value: &str) -> arkret_sdk::DidCoreId {
    crate::mls_api_helpers::principal_core_id(value)
        .unwrap_or_else(|error| panic!("fixture principal `{value}` is not a core id: {error}"))
}

/// Account authored at [`STATION_ID`].
pub(crate) fn authority(principal: &str) -> arkret_sdk::AccountId {
    authority_at_station(principal, STATION_ID)
}

/// Account authored at an explicit Station, for the tests whose subject is the
/// Station split itself (same principal, two servers).
pub(crate) fn authority_at_station(principal: &str, station: &str) -> arkret_sdk::AccountId {
    arkret_sdk::AccountId::new(core_id(principal), core_id(station))
}

/// Account authored at the Station the operation layer currently selects, for
/// tests that must agree with `crate::operation::authoring_station_id`.
pub(crate) fn authority_at_authoring_station(principal: &str) -> arkret_sdk::AccountId {
    arkret_sdk::AccountId::new(
        core_id(principal),
        crate::operation::authoring_station_id().expect("authoring station"),
    )
}

/// Complete account actor at [`STATION_ID`].
pub(crate) fn account_actor(principal: &str) -> arkret_sdk::ActorId {
    arkret_sdk::ActorId::account(authority(principal))
}

pub(crate) fn device_id(value: &str) -> arkret_sdk::DeviceId {
    arkret_sdk::DeviceId::new(value.to_owned())
        .unwrap_or_else(|error| panic!("fixture device `{value}` is invalid: {error}"))
}

/// Mark a locally generated KeyPackage as the exact authority-claimed record
/// consumed by an MLS Add. The MLS runtime intentionally refuses published
/// packages because only a claim gives the Welcome a durable recipient key.
pub(crate) fn claimed_mls_key_package(
    mut record: arkret_sdk::MlsKeyPackageRecord,
    issued_at_ms: u64,
) -> arkret_sdk::MlsKeyPackageRecord {
    record.state = arkret_sdk::MlsKeyPackageState::Claimed;
    record.claim_id = Some(arkret_wire::KeypackageClaimId::new_v7_at(issued_at_ms).to_string());
    record
}

fn detached_signature(
    context: arkret_sdk::DetachedSignatureContext,
    seed: u8,
) -> arkret_sdk::DetachedObjectSignature {
    arkret_sdk::DetachedObjectSignature {
        context,
        signature_algorithm: arkret_sdk::DetachedSignatureAlgorithm::Ed25519,
        verification_method: arkret_sdk::DidUrl::new("did:web:authority.example#key-1").unwrap(),
        signed_digest: arkret_sdk::Hash::new(format!(
            "sha256:{}",
            format!("{seed:02x}").repeat(32)
        ))
        .unwrap(),
        created_at: "2026-09-22T00:00:00.000Z".parse().unwrap(),
        sig: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode([seed; 64])).unwrap(),
    }
}

/// Wrap an SDK-produced Commit envelope in the two formal accepted carriers
/// consumed by MLS clients: the typed Event and its Station RealmCommit.
/// Signature verification is deliberately outside this fixture's scope; the
/// consumer APIs take an already verified `CommittedEventFullView`.
pub(crate) fn accepted_mls_commit(
    effective_scope: &arkret_sdk::ScopeRef,
    actor_id: arkret_sdk::ActorId,
    envelope: &arkret_sdk::MlsCommitEnvelope,
    base_group_state_ref: arkret_sdk::EventId,
    commit_seed: u8,
) -> arkret_sdk::CommittedEventFullView {
    let binding = arkret_sdk::MlsGovernanceBindingPayload::new(
        effective_scope.clone(),
        Some(base_group_state_ref.clone()),
        envelope.epoch.checked_sub(1).unwrap(),
        envelope.epoch,
        0,
    )
    .unwrap();
    accepted_mls_commit_with_binding(actor_id, envelope, binding, commit_seed)
}

pub(crate) fn accepted_mls_commit_with_binding(
    actor_id: arkret_sdk::ActorId,
    envelope: &arkret_sdk::MlsCommitEnvelope,
    binding: arkret_sdk::MlsGovernanceBindingPayload,
    commit_seed: u8,
) -> arkret_sdk::CommittedEventFullView {
    let effective_scope = binding.effective_scope().clone();
    let base_group_state_ref = binding.base_group_state_ref().unwrap().clone();
    let payload = arkret_sdk::MlsCommitPayload::new(
        base_group_state_ref.clone(),
        binding.key_access_revision(),
        envelope,
        binding,
    )
    .unwrap();
    let event = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::MlsCommit>::new(
        effective_scope.clone(),
        actor_id,
        payload,
    )
    .unwrap()
    .author_with_digest_suite(
        "2026-09-22T00:00:00.000Z".parse().unwrap(),
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap()
    .into_event();
    let realm_id = effective_scope.realm_id_opt().unwrap().clone();
    let stream_position = envelope.epoch;
    let commit = arkret_sdk::RealmCommit {
        commit_id: arkret_sdk::RealmCommitId::from_digest([commit_seed; 32]),
        realm_id: realm_id.clone(),
        stream_ref: arkret_sdk::CommitStreamRef::from_scope(&effective_scope, Some(realm_id))
            .unwrap(),
        stream_position,
        previous_commit_ref: Some(arkret_sdk::RealmCommitId::from_digest(
            [commit_seed.wrapping_sub(1); 32],
        )),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_sdk::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            base_group_state_ref,
        ),
        committed_at: "2026-09-22T00:00:01.000Z".parse().unwrap(),
        signature: detached_signature(
            arkret_sdk::DetachedSignatureContext::RealmCommit,
            commit_seed,
        ),
    };
    let accepted = arkret_sdk::CommittedEventFullView { commit, event };
    accepted.validate_shape().unwrap();
    accepted
}

/// Bind an SDK Welcome draft to the exact accepted Commit it accompanies.
/// The caller supplies the already authenticated recipient Actor because a
/// human MLS endpoint intentionally contains only the principal and device.
pub(crate) fn accepted_mls_welcome(
    draft: &arkret_sdk::MlsWelcomeDraft,
    recipient_actor_id: arkret_sdk::ActorId,
    accepted_commit: &arkret_sdk::CommittedEventFullView,
    delivery_time_ms: u64,
) -> arkret_sdk::MlsWelcomeDelivery {
    let recipient_endpoint = match &draft.recipient {
        arkret_sdk::MlsEndpointIdentity::HumanDevice { device_id, .. } => {
            arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
                device_id: device_id.clone(),
            }
        }
        arkret_sdk::MlsEndpointIdentity::AgentRuntime {
            verification_method,
            ..
        } => arkret_sdk::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: verification_method.clone(),
        },
        arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => {
            panic!("accepted Welcome fixture requires an authority-addressable endpoint")
        }
    };
    let delivery = arkret_sdk::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new_v7_at(delivery_time_ms),
        realm_id: accepted_commit.event.realm_id.clone(),
        effective_scope: accepted_commit.event.scope_ref.clone(),
        commit_event_ref: accepted_commit.event.event_id.clone(),
        recipient_actor_id,
        recipient_endpoint,
        keypackage_claim_ref: draft.keypackage_claim_ref.clone(),
        ciphertext_b64: draft.ciphertext_b64.clone(),
        producer_proof: detached_signature(
            arkret_sdk::DetachedSignatureContext::MlsWelcomeDelivery,
            0x77,
        ),
    };
    delivery.validate_shape().unwrap();
    delivery
}

pub(crate) fn realm_id(value: &str) -> arkret_sdk::RealmId {
    arkret_sdk::RealmId::new(value.to_owned())
        .unwrap_or_else(|error| panic!("fixture realm `{value}` is invalid: {error}"))
}

#[cfg(test)]
#[path = "test_support/committed_event.rs"]
pub(crate) mod committed_event;

/// Resolvable DID for a principal given in either accepted form.
///
/// `ActiveAccountContext::new` re-projects this DID and rejects the context
/// when it disagrees with the authority, so a fixture must derive both from the
/// same input rather than pairing an arbitrary DID with an arbitrary account.
pub(crate) fn did(principal: &str) -> arkret_sdk::Did {
    let value = match principal.strip_prefix("ak:did_core:web:") {
        Some(rest) => format!("did:web:{rest}"),
        None => principal.to_owned(),
    };
    arkret_sdk::Did::new(value.clone())
        .unwrap_or_else(|error| panic!("fixture principal `{value}` is not a DID: {error}"))
}

/// Builder for a signed-in account context.
///
/// The two call sites that needed one had drifted apart in every field that is
/// not load-bearing (profile id strategy, resolution metadata, default server),
/// which made it impossible to tell which differences were deliberate. The
/// builder keeps one construction path and makes each deviation an explicit
/// call.
pub(crate) struct AccountFixture {
    principal: String,
    station: String,
    profile_id: String,
    device: String,
    server_url: String,
    method_history_head: String,
    version_id: String,
    resolution_event_ref: String,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl AccountFixture {
    pub(crate) fn new(principal: &str) -> Self {
        Self {
            principal: principal.to_owned(),
            station: STATION_ID.to_owned(),
            profile_id: "ak:profile:019b0000-0000-7000-8000-000000000001".to_owned(),
            device: "ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
            server_url: "https://local.host".to_owned(),
            method_history_head: "head-1".to_owned(),
            version_id: "1".to_owned(),
            resolution_event_ref: format!("ak:event:{}", "A".repeat(44)),
            updated_at: chrono::Utc::now(),
        }
    }

    pub(crate) fn station(mut self, station: &str) -> Self {
        self.station = station.to_owned();
        self
    }

    pub(crate) fn profile_id(mut self, profile_id: String) -> Self {
        self.profile_id = profile_id;
        self
    }

    pub(crate) fn device(mut self, device: &str) -> Self {
        self.device = device.to_owned();
        self
    }

    pub(crate) fn server_url(mut self, server_url: &str) -> Self {
        self.server_url = server_url.to_owned();
        self
    }

    pub(crate) fn resolution(
        mut self,
        method_history_head: &str,
        version_id: &str,
        resolution_event_ref: &str,
    ) -> Self {
        self.method_history_head = method_history_head.to_owned();
        self.version_id = version_id.to_owned();
        self.resolution_event_ref = resolution_event_ref.to_owned();
        self
    }

    pub(crate) fn updated_at(mut self, updated_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.updated_at = updated_at;
        self
    }

    pub(crate) fn authority(&self) -> arkret_sdk::AccountId {
        authority_at_station(self.principal.as_str(), self.station.as_str())
    }

    pub(crate) fn build(self) -> crate::identity::active_account::ActiveAccountContext {
        let authority = self.authority();
        crate::identity::active_account::ActiveAccountContext::new(
            self.profile_id,
            authority,
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            arkret_sdk::PrincipalResolutionProjection {
                did: did(self.principal.as_str()),
                method_history_head: self.method_history_head,
                version_id: self.version_id,
                resolution_event_ref: self.resolution_event_ref,
                updated_at: self.updated_at,
            },
            device_id(self.device.as_str()),
            url::Url::parse(self.server_url.as_str()).expect("fixture server url"),
        )
        .expect("fixture account context")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_accepts_both_principal_id_forms() {
        let from_core = authority("ak:did_core:web:alice.example");
        let from_did = authority("did:web:alice.example");
        assert_eq!(from_core, from_did);
        assert_eq!(from_core.station_id.as_str(), STATION_ID);
    }

    #[test]
    fn station_split_produces_distinct_accounts() {
        let local = authority("ak:did_core:web:alice.example");
        let remote = authority_at_station("ak:did_core:web:alice.example", SERVER_STATION_ID);
        assert_ne!(local, remote);
        assert_eq!(local.principal_id, remote.principal_id);
    }
}

/// Install the authority-signed `CurrentSelector::MlsGroup` result for one
/// effective scope.
///
/// This is the single client-side evidence that a scope has an accepted
/// `ak.mls.genesis` and is therefore irreversibly RFC 9420: there is no
/// create-locked content scheme, encryption profile or epoch cell any more, so
/// the fixture installs exactly the current result the Realm snapshot carries.
pub(crate) fn install_accepted_mls_group(
    state: &mut crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
) {
    install_accepted_mls_group_at_epoch(state, effective_scope, 0, 0);
}

/// The same current result at an explicit epoch and key-access revision, for
/// tests that need a group past its genesis epoch.
pub(crate) fn install_accepted_mls_group_at_epoch(
    state: &mut crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    epoch: u64,
    key_access_revision: u64,
) {
    let realm_id = effective_scope.realm_id_opt().unwrap().to_string();
    let genesis_ref =
        arkret_sdk::EventId::new("ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap();
    let entry = serde_json::json!({
        "selector": {"kind": "mls_group", "scope_ref": effective_scope},
        "source_stream_ref": arkret_wire::CommitStreamRef::from_scope(effective_scope, None).unwrap(),
        "revision": {
            "commit_id": arkret_wire::RealmCommitId::from_digest([0x31; 32]),
            "stream_position": 1,
        },
        "value": {
            "effective_scope": effective_scope,
            "genesis_event_ref": genesis_ref,
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "current_mls_commit_event_ref": genesis_ref,
            "epoch": epoch,
            "current_key_access_revision": key_access_revision,
            "covered_key_access_revision": key_access_revision,
            "public_tree_ref": format!("ak:blob:sha256:{}", "a".repeat(64)),
        },
    });
    let entry: arkret_wire::TypedCurrentResult = serde_json::from_value(entry).unwrap();
    install_current_entries(state, &realm_id, vec![entry]);
}

/// Install a complete typed membership cut, replacing its previous member rows.
pub(crate) fn install_complete_joined_members(
    state: &mut crate::state::LocalStateStore,
    realm_id: &str,
    members: Vec<arkret_sdk::ActorId>,
) {
    let mut entries = state
        .realm_current_view_entries(realm_id)
        .unwrap_or_default();
    entries.retain(|entry| {
        !matches!(
            entry,
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::MemberState { .. },
                ..
            }
        )
    });
    for actor_id in members {
        entries.push(arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::MemberState { actor_id },
            source_stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: arkret_sdk::RealmId::new(realm_id).unwrap(),
            },
            revision: arkret_wire::CurrentRevision {
                commit_id: arkret_wire::RealmCommitId::from_digest([0x32; 32]),
                stream_position: 2,
            },
            value: serde_json::to_value(arkret_wire::MemberStateCurrent {
                membership: arkret_wire::MembershipState::Join,
                joined_at: Some("2026-09-27T00:00:00.000Z".parse().unwrap()),
            })
            .unwrap(),
        });
    }
    state
        .install_current_product_view(
            crate::current_projection::RealmCurrentView::new(realm_id, entries, true).unwrap(),
        )
        .unwrap();
}

/// Merge typed current rows into the store's installed product view of
/// `realm_id`, replacing any row with the same selector. This is the view the
/// sync engine installs from the durable current index.
pub(crate) fn install_current_entries(
    state: &mut crate::state::LocalStateStore,
    realm_id: &str,
    rows: Vec<arkret_wire::TypedCurrentResult>,
) {
    let selector = |entry: &arkret_wire::TypedCurrentResult| match entry {
        arkret_wire::TypedCurrentResult::Value { selector, .. } => selector.clone(),
    };
    let mut entries = state
        .realm_current_view_entries(realm_id)
        .unwrap_or_default();
    for row in rows {
        entries.retain(|existing| selector(existing) != selector(&row));
        entries.push(row);
    }
    state
        .install_current_product_view(
            crate::current_projection::RealmCurrentView::new(realm_id, entries, true).unwrap(),
        )
        .unwrap();
}

/// Complete SDK envelope for classification tests; not a signed restore proof.
pub(crate) fn key_backup_summary_fixture(body: &serde_json::Value) -> arkret_sdk::KeyBackupSummary {
    let backup: arkret_sdk::KeyBackup = serde_json::from_value(body.clone()).unwrap();
    arkret_sdk::KeyBackupSummary {
        backup_id: backup.backup_id,
        actor_id: backup.actor_id,
        device_id: backup.device_id,
        backup_kind: backup.backup_kind,
        backup_version: arkret_sdk::NonEmptyString::new(backup.backup_version).unwrap(),
        series_id: backup.series_id,
        series_seq: backup.series_seq,
        supersedes_id: backup.supersedes_id.map(Some),
        supersedes_digest: backup.supersedes_digest,
        expires_at: backup.expires_at.map(Some),
        created_at: backup.created_at,
        updated_at: backup.updated_at,
        ciphertext_digest: backup.ciphertext_digest,
        encryption: arkret_sdk::KeyBackupSummaryEncryption {
            recipient_method: backup.encryption.recipient_method,
            recipient_key_ref: backup.encryption.recipient_key_ref,
        },
        retention: None,
    }
}

pub(crate) fn key_backup_envelope_fixture(
    seq: u64,
    series: &str,
    item_kind: &str,
    recipient_method: &str,
) -> serde_json::Value {
    let value = serde_json::json!({
        "backup_id": format!("ak:backup:0196419b-0000-7000-8000-00000000003{seq}"),
        "actor_id": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:station.example"
            }
        },
        "backup_kind": "secret_storage",
        "backup_version": "kb_test_v1",
        "series_id": series,
        "series_seq": seq,
        "created_at": format!("2026-05-{:02}T00:00:00.000Z", seq + 1),
        "encryption": {
            "recipient_method": recipient_method,
            "aead": {"name": "chacha20_poly1305", "nonce": "AAAAAAAAAAAAAAAA"}
        },
        "domain_separation": {"subdomain": "key_backup"},
        "contents": [{"item_kind": item_kind, "secret_id": "test_secret"}],
        "ciphertext": "AA",
        "ciphertext_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "auth_data": {
            "device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "verification_method": "did:web:alice.example#device",
            "signature_algorithm": "Ed25519",
            "signature": "AA",
            "device_authorize_event_id": "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD"
        }
    });
    let backup: arkret_sdk::KeyBackup =
        serde_json::from_value(value).expect("complete SDK backup envelope fixture");
    serde_json::to_value(backup).unwrap()
}
