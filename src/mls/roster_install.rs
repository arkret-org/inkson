//! Complete historical authority check before a joined MLS group may acquire
//! leaf bindings. The service roster is data until every signature, public
//! Genesis byte and occupied leaf has been checked against the accepted cut.

use arkret_sdk::{
    ActorId, AuthenticatedServiceResolution, DidCoreId, EventId, MlsGroupStateMaterialOutcome,
    MlsMemberGroupStateMaterialReadRequestBody, MlsRosterAuthorityReadOutcome,
    MlsRosterAuthorityReadRequestBody,
};

/// Obtain the signed historical authority for an accepted Welcome at the
/// target Commit cut. Each signed Add record carries the original recipient
/// Station's frozen method history for independent receipt and attestation
/// verification; the current governance route only verifies the manifest.
pub(crate) async fn install_welcome_roster_from_service(
    api: &crate::transport::TransportClient,
    group: &mut arkret_sdk::ArkretMlsGroup,
    accepted_commit: &arkret_wire::CommittedEventFullView,
    authority: &arkret_sdk::AccountId,
) -> Result<(), String> {
    let transition = crate::mls::accepted_artifact::accepted_mls_transition(accepted_commit)?;
    let scope = &transition.effective_scope;
    let realm_id = scope
        .realm_id_opt()
        .ok_or_else(|| "MLS roster requires a Realm or Circle scope".to_owned())?;
    let http = api.http();
    let authority_client = garth::AuthorityClient::new(http.clone());
    let (bundle, freshness, mut replica) =
        crate::realm_events_engine::fresh_verified_realm(&authority_client, http, realm_id)
            .await
            .map_err(|error| format!("verify current MLS governance Station: {error}"))?;
    let current = if matches!(scope, arkret_sdk::ScopeRef::Realm { .. })
        && bundle.current_service_id != authority.station_id
    {
        let rows = crate::realm_events_engine::verified_realm_roster_history(
            http,
            &bundle,
            &freshness,
            &mut replica,
        )
        .await
        .map_err(|error| format!("verify MLS roster Realm history: {error}"))?;
        roster_basis_from_realm_history(&rows, accepted_commit)?
    } else {
        let snapshot = http
            .realm_state_snapshot_head(realm_id)
            .await
            .map_err(|error| format!("read MLS roster current Snapshot: {error}"))?;
        let keys =
            garth::fetch_historical_station_key_directory(http, &bundle, None, Some(&snapshot))
                .await
                .map_err(|error| format!("read MLS roster Station history: {error}"))?;
        let fresh = arkret_identity::RealmAuthorityFreshness::new(
            chrono::Utc::now(),
            freshness.expected_nonce.clone(),
        );
        replica
            .install_verified_current_snapshot_heads(&snapshot, &fresh, &keys)
            .map_err(|error| format!("verify MLS roster current Snapshot: {error}"))?;
        let groups = snapshot
            .current_state_entries
            .iter()
            .filter_map(|row| match row {
                arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref },
                    value,
                    ..
                } if scope_ref == scope => Some(value),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [value] = groups.as_slice() else {
            return Err("MLS roster has no unique signed scope current".to_owned());
        };
        let current: arkret_wire::MlsGroupCurrent = serde_json::from_value((*value).clone())
            .map_err(|error| format!("decode signed MLS scope current: {error}"))?;
        if &current.effective_scope != scope {
            return Err("signed MLS current names another scope".to_owned());
        }
        RosterCurrentBasis {
            genesis_event_ref: current.genesis_event_ref,
            head_event_ref: current.current_mls_commit_event_ref,
            epoch: current.epoch,
        }
    };
    if accepted_commit.event.kind != arkret_sdk::EventKind::MlsCommit
        || current.epoch < transition.next_epoch
        || group.epoch() != transition.next_epoch
        || group.group_id() != transition.mls_group_id
    {
        return Err("MLS roster target differs from the accepted Welcome cut".to_owned());
    }
    let governance_resolution: AuthenticatedServiceResolution =
        serde_json::from_value(bundle.current_route_record)
            .map_err(|error| format!("MLS governance route is not a closed resolution: {error}"))?;
    if governance_resolution.service_id != bundle.current_service_id {
        return Err("MLS governance resolution belongs to another Station".to_owned());
    }
    let request = MlsRosterAuthorityReadRequestBody {
        realm_id: realm_id.clone(),
        effective_scope: scope.clone(),
        mls_group_id: transition.mls_group_id,
        genesis_event_ref: current.genesis_event_ref,
        target_commit_event_ref: accepted_commit.event.event_id.clone(),
        target_epoch: transition.next_epoch,
        caller_actor_id: ActorId::account(authority.clone()),
        cursor: None,
    };
    let pages = crate::transport::EndpointClients::new(api.clone())
        .mls()
        .unverified_member_roster_authority_pages(&request)
        .await
        .map_err(|error| format!("read complete MLS roster: {error}"))?;
    let manifest = &pages
        .first()
        .ok_or_else(|| "MLS roster has no signed page".to_owned())?
        .manifest;
    arkret_sdk::verify_mls_roster_authority_manifest_signature(
        manifest,
        &request,
        &bundle.current_service_id,
        &current.head_event_ref,
        &governance_resolution,
    )
    .map_err(|error| format!("verify MLS roster manifest: {error}"))?;
    arkret_sdk::verify_mls_roster_authority_pages(
        &pages,
        &request,
        &bundle.current_service_id,
        &current.head_event_ref,
        &governance_resolution,
    )
    .map_err(|error| format!("verify complete historical MLS roster: {error}"))?;
    let material_request = genesis_material_request(&request, manifest);
    let material = http
        .self_mls_group_state_material(&material_request)
        .await
        .map_err(|error| format!("read accepted MLS Genesis material: {error}"))?;
    install_signed_roster_bindings(
        group,
        &pages,
        &request,
        &bundle.current_service_id,
        &current.head_event_ref,
        &governance_resolution,
        &material,
    )
}

struct RosterCurrentBasis {
    genesis_event_ref: EventId,
    head_event_ref: EventId,
    epoch: u64,
}

/// The caller has verified the continuous rows through its fresh Realm head.
/// An undisclosed suffix cannot prove that no later MLS transition exists.
fn roster_basis_from_realm_history(
    rows: &[arkret_wire::CommittedEventView],
    target: &arkret_wire::CommittedEventFullView,
) -> Result<RosterCurrentBasis, String> {
    if !matches!(target.event.scope_ref, arkret_wire::ScopeRef::Realm { .. }) {
        return Err("Realm roster history cannot prove an independent scope".to_owned());
    }
    let mut basis: Option<RosterCurrentBasis> = None;
    let mut target_found = false;
    for row in rows {
        if row.commit().realm_id != target.event.realm_id
            || row.commit().stream_ref != target.commit.stream_ref
        {
            return Err("MLS roster history names another Realm stream".to_owned());
        }
        let full = match row {
            arkret_wire::CommittedEventView::Full(full) => full,
            arkret_wire::CommittedEventView::Withheld(_) if basis.is_none() => continue,
            arkret_wire::CommittedEventView::Withheld(_) => {
                return Err("MLS current cannot be proved across an undisclosed suffix".to_owned());
            }
        };
        if full.event.realm_id != target.event.realm_id
            || full.commit.stream_ref != target.commit.stream_ref
        {
            return Err("MLS roster history names another Realm stream".to_owned());
        }
        if full.event.event_id == target.event.event_id {
            if full != target {
                return Err("MLS roster target differs from its verified history row".to_owned());
            }
            target_found = true;
        }
        if !matches!(
            full.event.kind,
            arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit
        ) {
            continue;
        }
        let transition = crate::mls::accepted_artifact::accepted_mls_transition(full)?;
        if transition.effective_scope != target.event.scope_ref {
            return Err("MLS roster history crosses an independent scope".to_owned());
        }
        match (&mut basis, &full.event.kind) {
            (None, arkret_wire::EventKind::MlsGenesis) => {
                basis = Some(RosterCurrentBasis {
                    genesis_event_ref: full.event.event_id.clone(),
                    head_event_ref: full.event.event_id.clone(),
                    epoch: transition.next_epoch,
                });
            }
            (None, arkret_wire::EventKind::MlsCommit)
                if full == target && transition.previous_epoch == 0 =>
            {
                // The accepted first Add extends the unique epoch-0 Genesis.
                // Its signed base survives a member's since-join history floor.
                let payload: arkret_sdk::MlsCommitPayload = serde_json::from_value(
                    serde_json::to_value(&full.event.payload).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                basis = Some(RosterCurrentBasis {
                    genesis_event_ref: payload.base_group_state_ref().clone(),
                    head_event_ref: full.event.event_id.clone(),
                    epoch: transition.next_epoch,
                });
            }
            (Some(current), arkret_wire::EventKind::MlsCommit)
                if transition.previous_epoch == current.epoch =>
            {
                let payload: arkret_sdk::MlsCommitPayload = serde_json::from_value(
                    serde_json::to_value(&full.event.payload).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                if payload.base_group_state_ref() != &current.head_event_ref {
                    return Err("MLS roster Commit does not extend its verified base".to_owned());
                }
                current.head_event_ref = full.event.event_id.clone();
                current.epoch = transition.next_epoch;
            }
            _ => return Err("MLS roster history has no unique continuous Genesis".to_owned()),
        }
    }
    if !target_found {
        return Err("MLS roster target is absent from the verified read cut".to_owned());
    }
    basis.ok_or_else(|| "MLS roster Genesis is not disclosed at this read cut".to_owned())
}

#[cfg(test)]
mod roster_history_tests {
    use serde_json::{Value, json};

    use super::*;

    fn genesis_payload(realm: &arkret_sdk::RealmId) -> Value {
        serde_json::to_value(arkret_sdk::MlsGenesisPayload {
            cipher_suite: arkret_wire::NonEmptyString::new(
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            )
            .unwrap(),
            group_info_ref: arkret_wire::BlobRef::new(format!("ak:blob:sha256:{}", "1".repeat(64)))
                .unwrap(),
            ratchet_tree_ref: arkret_wire::BlobRef::new(format!(
                "ak:blob:sha256:{}",
                "2".repeat(64)
            ))
            .unwrap(),
            creator_leaf_authority: arkret_sdk::MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_b64u: arkret_wire::Base64UrlString::new(
                    arkret_sdk::base64url_encode([7; 32]),
                )
                .unwrap(),
                endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                    device_id: arkret_wire::DeviceId::new(
                        "ak:device:0196419b-0000-7000-8000-000000000001",
                    )
                    .unwrap(),
                },
                authorization_event_ref: EventId::from_digest(
                    arkret_sdk::canonical::DigestSuite::Sha256,
                    [3; 32],
                ),
            },
            governance_binding: arkret_sdk::MlsGovernanceBindingPayload::realm(
                realm.clone(),
                None,
                0,
                0,
                0,
            )
            .unwrap(),
            created_at: crate::test_support::committed_event::fixture_time(2),
        })
        .unwrap()
    }

    fn commit_payload(realm: &arkret_sdk::RealmId, base: &EventId, previous: u64) -> Value {
        let payload: arkret_sdk::MlsCommitPayload = serde_json::from_value(json!({
            "base_group_state_ref": base,
            "previous_epoch": previous,
            "next_epoch": previous + 1,
            "covers_key_access_revision": 0,
            "commit_bytes_b64": "AA",
            "governance_binding": arkret_sdk::MlsGovernanceBindingPayload::realm(
                realm.clone(), Some(base.clone()), previous, previous + 1, 0,
            ).unwrap(),
        }))
        .unwrap();
        serde_json::to_value(payload).unwrap()
    }

    fn fixture() -> Vec<arkret_wire::CommittedEventFullView> {
        let realm =
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        let genesis = genesis_payload(&realm);
        let first = crate::test_support::committed_event::verified_realm_item(
            realm.clone(),
            "ak.mls.genesis",
            genesis.clone(),
        );
        let commit = commit_payload(&realm, &first.event.event_id, 0);
        let items = crate::test_support::committed_event::verified_realm_items(
            realm,
            vec![
                ("ak.mls.genesis".to_owned(), genesis),
                ("ak.mls.commit".to_owned(), commit),
            ],
        );
        assert_eq!(items[0], first);
        items
    }

    fn rows(items: &[arkret_wire::CommittedEventFullView]) -> Vec<arkret_wire::CommittedEventView> {
        items
            .iter()
            .cloned()
            .map(arkret_wire::CommittedEventView::Full)
            .collect()
    }

    #[test]
    fn complete_signed_realm_mls_history_proves_genesis_and_current_head() {
        let items = fixture();
        let basis = roster_basis_from_realm_history(&rows(&items), &items[1]).unwrap();
        assert_eq!(basis.genesis_event_ref, items[0].event.event_id);
        assert_eq!(basis.head_event_ref, items[1].event.event_id);
        assert_eq!(basis.epoch, 1);
    }

    #[test]
    fn first_accepted_add_proves_genesis_without_reading_prejoin_event() {
        let items = fixture();
        let basis = roster_basis_from_realm_history(&rows(&items[1..]), &items[1]).unwrap();
        assert_eq!(basis.genesis_event_ref, items[0].event.event_id);
        assert_eq!(basis.head_event_ref, items[1].event.event_id);
        assert_eq!(basis.epoch, 1);
    }

    #[test]
    fn missing_target_or_disclosed_suffix_cannot_prove_mls_current() {
        let items = fixture();
        assert!(roster_basis_from_realm_history(&rows(&items[..1]), &items[1]).is_err());
        let mut hidden = rows(&items);
        hidden[1] =
            arkret_wire::CommittedEventView::Withheld(arkret_wire::CommittedEventWithheldView {
                commit: items[1].commit.clone(),
                event_disclosure: arkret_wire::EventDisclosure {
                    status: arkret_wire::EventDisclosureStatus::Withheld,
                },
            });
        assert!(roster_basis_from_realm_history(&hidden, &items[1]).is_err());
        let mut duplicate = rows(&items);
        duplicate.insert(1, duplicate[0].clone());
        assert!(roster_basis_from_realm_history(&duplicate, &items[1]).is_err());
        let mut other_target = items[1].clone();
        other_target.commit.commit_id = arkret_wire::RealmCommitId::from_digest([99; 32]);
        assert!(roster_basis_from_realm_history(&rows(&items), &other_target).is_err());
    }

    #[test]
    fn mls_epoch_gaps_and_wrong_base_refs_are_not_current_proofs() {
        let items = fixture();
        let realm = &items[0].event.realm_id;
        for payload in [
            commit_payload(realm, &items[1].event.event_id, 2),
            commit_payload(realm, &items[0].event.event_id, 1),
        ] {
            let mut entries = items
                .iter()
                .map(|item| {
                    (
                        item.event.kind.as_str().to_owned(),
                        serde_json::to_value(&item.event.payload).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            entries.push(("ak.mls.commit".to_owned(), payload));
            let history =
                crate::test_support::committed_event::verified_realm_items(realm.clone(), entries);
            assert!(roster_basis_from_realm_history(&rows(&history), &history[1]).is_err());
        }
    }
}

fn genesis_material_request(
    request: &MlsRosterAuthorityReadRequestBody,
    manifest: &arkret_sdk::MlsRosterAuthorityManifest,
) -> MlsMemberGroupStateMaterialReadRequestBody {
    MlsMemberGroupStateMaterialReadRequestBody {
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        epoch: Default::default(),
        group_state_event_id: request.genesis_event_ref.clone(),
        caller_actor_id: request.caller_actor_id.clone(),
        target_commit_event_ref: request.target_commit_event_ref.clone(),
        target_epoch: request.target_epoch,
        group_info_ref: manifest.group_info_ref.clone(),
        ratchet_tree_ref: manifest.ratchet_tree_ref.clone(),
        max_response_bytes: None,
    }
}

/// Verify a complete signed roster and the exact Genesis public material,
/// then install an every-and-only binding map for the already verified joined
/// RFC group. The caller must obtain `request` and `expected_head` from the
/// accepted target/current cut, not from a Welcome or an untrusted page.
pub(crate) fn install_signed_roster_bindings(
    group: &mut arkret_sdk::ArkretMlsGroup,
    pages: &[MlsRosterAuthorityReadOutcome],
    request: &MlsRosterAuthorityReadRequestBody,
    expected_governance: &DidCoreId,
    expected_head: &EventId,
    governance_resolution: &AuthenticatedServiceResolution,
    material: &MlsGroupStateMaterialOutcome,
) -> Result<(), String> {
    arkret_sdk::install_verified_mls_roster_bindings(
        group,
        pages,
        request,
        expected_governance,
        expected_head,
        governance_resolution,
        material,
    )
}
