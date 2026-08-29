//! Realm lifecycle / update / organization / message-revise builders.

use arkret_models_collaboration::events_payloads::{
    RealmOrganizationAuthorization, RealmOrganizationControlScope, RealmOrganizationPayload,
    RealmOrganizationRelationship, RealmOrganizationStatus,
};

use super::{TypedOperationBuilder, realm_id_value, space_id_value};

/// Build a `ak.space.archive` operation against a container Space. The
/// Space transitions from `Active` to `Archived`; reversible via
/// `space_restore`. Spec: `models/realm-and-space.md` §4.4. The wire
/// payload uses canonical `space_id`.
pub fn realm_archive(
    realm_id: &str,
    actor: &str,
    container_space_id: &str,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::SpaceStateTransitionPayload {
        space_id: space_id_value(container_space_id)?,
        reason: None,
        effective_at: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::SpaceArchive>(
            realm_id, actor, payload,
        )
        .target_ref(container_space_id),
    )
}

/// Build a `ak.message.revise` operation carrying the replacement content
/// block required by `message_revise_payload`.
///
/// `message_id` is the single registered target carrier: an `ak:event:` token
/// is retyped to `ak:message:` (`common-fields.md` §6.0) before it is written.
pub fn message_revise_content(
    realm_id: &str,
    actor: &str,
    target_ref: &str,
    content: arkret_sdk::ContentBlock,
) -> anyhow::Result<TypedOperationBuilder> {
    let message_id = message_id_from_target_ref(target_ref)?;
    let payload = arkret_sdk::MessageRevisePayload {
        message_id: message_id.clone(),
        track_name: None,
        content: Some(content),
        encrypted_content: None,
        metadata: None,
        encrypted_metadata: None,
        reason: None,
        mimi_provenance: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageRevise>(
            realm_id, actor, payload,
        )
        .target_ref(message_id.as_str()),
    )
}

/// Retype an `ak:event:` create-Event token to the `ak:message:` typed ID that
/// the Message-scoped payload classes register as their only target carrier.
fn message_id_from_target_ref(target_ref: &str) -> anyhow::Result<arkret_sdk::MessageId> {
    let candidate = match target_ref.strip_prefix("ak:event:") {
        Some(token) => format!("ak:message:{token}"),
        None => target_ref.to_owned(),
    };
    arkret_sdk::MessageId::new(candidate)
        .map_err(|err| anyhow::anyhow!("invalid message_id {target_ref:?}: {err}"))
}

/// Build a `ak.realm.organization` statement operation (YGN-ORG-02).
///
/// Constructs the spec-canonical [`RealmOrganizationPayload`] via the SDK
/// strong type — the client never hand-rolls the wire object. Supports both
/// `active` (assert / endorse a relationship) and `revoked` (withdraw a prior
/// statement) via `status`.
///
/// Authorization rule (acceptance criterion): the organization proof is NOT
/// produced from the local human login session. The caller passes an
/// [`RealmOrganizationAuthorization`] obtained from the
/// organization-side authorization result (coauth / DID controller). This
/// builder only assembles + locally validates the statement; it performs no
/// signing.
///
/// For `status == Revoked`, `revokes_statement_id` is REQUIRED. For
/// `status == Active`, it MUST be absent — both are enforced by
/// [`RealmOrganizationPayload`] downstream and re-checked here for fail-fast
/// client feedback.
///
/// Returns an error (does not panic) when ids are non-canonical, when
/// `control_scopes` is empty, or when the status / revocation / delegation
/// invariants are violated.
#[allow(clippy::too_many_arguments)]
pub fn realm_organization_statement(
    realm_id: &str,
    actor: &str,
    statement_id: &str,
    organization_id: &arkret_sdk::DidCoreId,
    relationship: RealmOrganizationRelationship,
    status: RealmOrganizationStatus,
    control_scopes: Vec<RealmOrganizationControlScope>,
    issued_at: chrono::DateTime<chrono::Utc>,
    authorization: RealmOrganizationAuthorization,
    revokes_statement_id: Option<String>,
) -> anyhow::Result<TypedOperationBuilder> {
    if control_scopes.is_empty() {
        anyhow::bail!("ak.realm.organization control_scopes must not be empty");
    }
    // Local fail-fast on the status / revocation coupling. The same invariant
    // is re-enforced by the SDK verifier server-side; surfacing it here gives
    // the UI an immediate, deterministic error.
    match (status, &revokes_statement_id) {
        (RealmOrganizationStatus::Revoked, None) => {
            anyhow::bail!("ak.realm.organization revoked status requires revokes_statement_id");
        }
        (RealmOrganizationStatus::Active, Some(_)) => {
            anyhow::bail!(
                "ak.realm.organization active status must not carry revokes_statement_id"
            );
        }
        _ => {}
    }
    // Issuer-role / delegation coupling (mirrors the SDK statement verifier):
    // delegated roles MUST carry a delegation_ref; non-delegated roles MUST
    // NOT. We reject early so a malformed authorization never reaches the wire.
    match (
        authorization.issuer_role.requires_delegation_ref(),
        &authorization.delegation_ref,
    ) {
        (true, None) => {
            anyhow::bail!(
                "ak.realm.organization issuer_role {:?} requires authorization.delegation_ref",
                authorization.issuer_role
            );
        }
        (false, Some(_)) => {
            anyhow::bail!(
                "ak.realm.organization delegation_ref only valid for delegated issuer_role"
            );
        }
        _ => {}
    }

    let payload = RealmOrganizationPayload {
        statement_id: statement_id.to_owned(),
        realm_id: realm_id_value(realm_id)?,
        organization_id: organization_id.clone(),
        relationship,
        status,
        control_scopes,
        issued_at,
        not_before: None,
        expires_at: None,
        supersedes_statement_id: None,
        revokes_statement_id,
        realm_frontier_digest: None,
        organization_policy_ref: None,
        authorization,
    };

    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmOrganization>(
            realm_id, actor, payload,
        )
        .target_ref(organization_id.as_str()),
    )
}
