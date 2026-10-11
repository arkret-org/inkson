//! Capability grant / revoke builders.

use arkret_models_collaboration::governance::authorization::{
    EffectiveCapabilityGrantRow, GrantList,
};
use arkret_models_integration::AppletCapabilityRevokeIntent;
use arkret_wire::{CurrentRevision, event_kind_str};
use serde_json::Value;

use super::{TypedOperationBuilder, trim_realm_id};

/// The signed lineage for a Realm-root capability grant. The governing Station
/// checks current authority at acceptance; its service id and commit basis are
/// not producer-authored fields in `issuer_authority_refs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerRealmAuthorityBasis {
    pub authority_generation: u64,
    pub authority_event_ref: arkret_sdk::EventId,
}

/// Legacy no-current entry point retained only so forbidden callers fail
/// closed before Event construction. New callers must use one of the two
/// carrier-specific builders below.
pub fn capability_revoke(
    _realm_id: &str,
    _actor: &str,
    _grant_id: &str,
    _reason: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    anyhow::bail!(
        "capability revoke blocked: exact accepted CurrentRevision is unavailable; read an \
         EffectiveCapabilityGrantRow or use an Applet revoke preview intent"
    )
}

fn capability_revoke_exact(
    realm_id: &str,
    actor: &str,
    grant_id: &arkret_sdk::GrantId,
    expected_revision: &CurrentRevision,
    reason: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::CapabilityRevokePayload {
        grant_id: grant_id.clone(),
        expected_revision: expected_revision.clone(),
        reason: reason.map(ToOwned::to_owned),
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::CapabilityRevoke>(
            realm_id, actor, payload,
        )
        .target_ref(grant_id.as_str()),
    )
}

/// Select exactly one active Grant row returned by
/// `ak.self.authz.grants.read.effective.v1`.
///
/// The surrounding list digest, local projection and historical Event ids are
/// deliberately not accepted as authoring inputs.
pub fn effective_grant_row_for_revoke<'a>(
    list: &'a GrantList,
    grant_id: &str,
) -> anyhow::Result<&'a EffectiveCapabilityGrantRow> {
    let grant_id = arkret_sdk::GrantId::new(grant_id.to_owned())
        .map_err(|error| anyhow::anyhow!("capability revoke grant_id {grant_id:?}: {error}"))?;
    let mut matches = list.grants.iter().filter(|row| row.grant.id == grant_id);
    let row = matches.next().ok_or_else(|| {
        anyhow::anyhow!(
            "capability revoke blocked: governing Station returned no active effective row for {}",
            grant_id.as_str()
        )
    })?;
    if matches.next().is_some() {
        anyhow::bail!(
            "capability revoke blocked: governing Station returned duplicate effective rows for {}",
            grant_id.as_str()
        );
    }
    Ok(row)
}

/// Author a manual admin revoke only from the exact active Grant row returned
/// by the governing Station.
pub fn capability_revoke_from_effective_row(
    realm_id: &str,
    actor: &str,
    row: &EffectiveCapabilityGrantRow,
    reason: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))?;
    if row.grant.realm_id.as_ref() != Some(&realm_id) {
        anyhow::bail!(
            "capability revoke blocked: effective Grant row does not belong to Realm {}",
            realm_id.as_str()
        );
    }
    capability_revoke_exact(
        realm_id.as_str(),
        actor,
        &row.grant.id,
        &row.revision,
        reason,
    )
}

/// Dedicated issuer withdrawal accepts an ineffective current row, but never
/// a terminal grant, another issuer's grant or a guessed CAS revision.
pub fn capability_revoke_from_owned_current(
    realm_id: &str,
    actor: &str,
    row: &arkret_sdk::exact_current_results::CapabilityGrantExactCurrentRow,
    reason: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = arkret_sdk::RealmId::new(trim_realm_id(realm_id))?;
    let signer = super::actor_id(actor)?;
    if row.value.realm_id.as_ref() != Some(&realm)
        || row.source_stream_ref
            != (arkret_sdk::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            })
        || row.selector.grant_id != row.value.id
        || row.value.owned_agent_issuer() != signer.as_account_id()
        || row.value.owned_agent_issuer().is_none()
        || row.value.status != arkret_sdk::CapabilityGrantStatus::Active
    {
        anyhow::bail!(
            "owned Agent revoke requires the original issuer's exact nonterminal current"
        );
    }
    capability_revoke_exact(realm.as_str(), actor, &row.value.id, &row.revision, reason)
}

/// Author an Applet revoke Event by copying the exact revision and reason from
/// the canonical preview intent. The caller must submit these unchanged with
/// the preview plan digest so the Station can recompute and compare the plan.
pub fn capability_revoke_from_applet_preview(
    realm_id: &str,
    actor: &str,
    intent: &AppletCapabilityRevokeIntent,
) -> anyhow::Result<TypedOperationBuilder> {
    if intent.event_kind != event_kind_str::CAPABILITY_REVOKE {
        anyhow::bail!(
            "Applet revoke blocked: preview intent event_kind must be {}",
            event_kind_str::CAPABILITY_REVOKE
        );
    }
    capability_revoke_exact(
        realm_id,
        actor,
        &intent.grant_id,
        &intent.expected_revision,
        Some(intent.reason_code.as_str()),
    )
}

/// `ak.capability.grant` event carrying the canonical
/// `capability_grant_payload` wrapper (`{grant_id, grant:{…}}`) the P1
/// coland reducer (`apply_capability`) reads `issuer` / `subject` /
/// `actions` / `resources` from. This is the only capability-grant
/// builder: every directed grant (e.g. setting a Realm admin via
/// `actions=[ak.realm.admin]`, or an admin-panel capability grant to a
/// `subject`) carries the full grant object, because the reducer fails
/// closed on a grant body with no `issuer` or no `actions`.
///
/// `subject` is the delegee's complete account; `actor` is the issuer (and
/// the Envelope signer). The subject is closed by the caller (resolved from
/// the Realm roster or pasted as the canonical selector) because a grant to
/// `(principal, this Station)` for a member hosted elsewhere would name an
/// account that is not in the Realm at all (account-lifecycle.md §156).
/// `resources` defaults to a single
/// `{kind:"realm", realm_id}` selector — the management surface this
/// covers. The Envelope `seal_basis` / signature carries the issuer
/// proof; the per-grant `proofs[]` the strict SDK builder mints is not
/// re-derived here (consistent with the rest of the inkson `ak_ops`
/// event pipeline, which signs at the Envelope boundary).
pub fn capability_grant_actions(
    realm_id: &str,
    actor: &str,
    subject: &arkret_sdk::AccountId,
    actions: &[&str],
    expires_at: Option<&str>,
    constraints: Value,
    root_basis: &IssuerRealmAuthorityBasis,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    capability_grant_actions_with_resources(
        &realm,
        actor,
        subject,
        actions,
        vec![arkret_sdk::WireResourceSelector::realm(
            arkret_sdk::RealmId::new(realm.clone())?,
        )],
        expires_at,
        constraints,
        root_basis,
    )
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
/// Build a capability grant with caller-supplied canonical resource selectors.
/// Participation uses this form for Circle and Strand scopes; the ordinary
/// Realm-admin helper above keeps its Realm-wide default.
pub fn capability_grant_actions_with_resources(
    realm_id: &str,
    actor: &str,
    subject: &arkret_sdk::AccountId,
    actions: &[&str],
    resources: Vec<arkret_sdk::WireResourceSelector>,
    expires_at: Option<&str>,
    constraints: Value,
    root_basis: &IssuerRealmAuthorityBasis,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let realm_typed = arkret_sdk::RealmId::new(realm.clone())?;
    let actor_typed = crate::mls_api_helpers::principal_core_id(actor)?;
    let expires_at = expires_at
        .map(str::parse)
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid capability grant expires_at: {error}"))?;
    let mut constraints_typed = if constraints.is_null() {
        Vec::new()
    } else {
        serde_json::from_value::<Vec<arkret_sdk::GrantConstraint>>(constraints)?
    };
    if let Some(expires_at) = expires_at {
        let mut temporal = arkret_sdk::GrantConstraint::new(
            arkret_sdk::GrantConstraintKind::Temporal,
            arkret_sdk::GrantConstraintEffect::Allow,
        );
        temporal.expires_at = Some(expires_at);
        constraints_typed.push(temporal);
    }
    let station_id = crate::operation::authoring_station_id()?;
    let grant = arkret_sdk::CapabilityGrantCreateBody {
        schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
        realm_id: Some(realm_typed.clone()),
        issuer_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            actor_typed,
            station_id,
        )),
        subject: arkret_sdk::CapabilitySubject::Actor(arkret_sdk::ActorId::account(
            subject.clone(),
        )),
        actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        resources,
        constraints: constraints_typed,
        // The Station resolves and locks current authority at acceptance. The
        // signed payload carries only closed semantic lineage.
        issuer_authority_refs: vec![arkret_sdk::IssuerAuthorityRef::RealmRoot {
            realm_id: realm_typed,
            authority_event_ref: root_basis.authority_event_ref.clone(),
            authority_generation: root_basis.authority_generation,
        }],
        issued_at: crate::clock::now_utc_millis(),
    };
    let payload = arkret_sdk::CapabilityGrantPayload { grant };
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::CapabilityGrant,
    >(&realm, actor, payload))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn authority_basis(generation: u64) -> IssuerRealmAuthorityBasis {
        IssuerRealmAuthorityBasis {
            authority_generation: generation,
            authority_event_ref: arkret_sdk::EventId::new(
                "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            )
            .unwrap(),
        }
    }

    #[test]
    fn grant_binds_the_committed_realm_authority_decision() {
        let operation = capability_grant_actions(
            "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "did:web:issuer.example",
            &crate::test_support::authority("did:web:subject.example"),
            &["ak.message.create"],
            None,
            Value::Null,
            &authority_basis(1),
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();
        assert_eq!(
            operation.payload()["grant"]["issuer_authority_refs"],
            json!([{
                "kind": "realm_root",
                "realm_id": "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
                "authority_generation": 1,
                "authority_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            }])
        );
    }

    #[test]
    fn a_later_authority_generation_produces_a_different_issuer_ref() {
        let build = |generation: u64| {
            capability_grant_actions(
                "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
                "did:web:issuer.example",
                &crate::test_support::authority("did:web:subject.example"),
                &["ak.realm.admin"],
                None,
                Value::Null,
                &authority_basis(generation),
            )
            .unwrap()
            .build_sdk_event("inkson")
            .unwrap()
            .payload()["grant"]["issuer_authority_refs"]
                .clone()
        };
        assert_ne!(build(0), build(1));
    }
}
