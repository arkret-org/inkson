//! Realm lifecycle / update / organization / message-revise builders.

use cokret_sdk::models::{
    RealmOrganizationAuthorization, RealmOrganizationControlScope, RealmOrganizationIssuerRole,
    RealmOrganizationPayload, RealmOrganizationRelationship, RealmOrganizationStatus,
    SignatureMaterial,
};
use serde_json::json;

use super::{
    OperationBuilder, did_id, object_patch_payload_value, patch_from_value, realm_id_value,
};

/// Build a `ck.space.archive` operation against a container Space. The
/// Space transitions from `Active` to `Archived`; reversible via
/// `space_restore`. Spec: `models/realm-and-space.md` §4.4. The wire
/// payload uses canonical `space_id`.
pub fn realm_archive(realm_id: &str, actor: &str, container_space_id: &str) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::SpaceArchive,
    )
    .target_ref(container_space_id)
    .body(json!({ "space_id": container_space_id }))
}

/// Build a `ck.message.revise` patch operation. Spec: revise is
/// supposed to carry `payload.patch` like the other `*.update`
/// events. New clients emit patches; full-content revise payloads are
/// outside the client write contract.
pub fn message_revise_patch(
    realm_id: &str,
    actor: &str,
    message_id: &str,
    patch: serde_json::Value,
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MessageRevise,
    )
    .target_ref(message_id)
    .body(json!({
        "message_id": message_id,
        "patch": patch,
    }))
}

/// Build a `ck.realm.update` patch operation. The reducer accepts
/// both flat fields (action/owner/title/security_class) and
/// `payload.patch`; the patch shape is preferred for non-lifecycle
/// edits (title / description).
pub fn realm_update_patch(
    envelope_realm_id: &str,
    actor: &str,
    realm_id: &str,
    patch: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let patch = patch_from_value(patch)?;
    Ok(OperationBuilder::new(
        envelope_realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::RealmUpdate,
    )
    .target_ref(realm_id)
    .body(object_patch_payload_value(realm_id, patch)?))
}

/// `ck.realm.update` patch event carrying Realm metadata (name / topic /
/// description / etc.). This is a plain Realm metadata patch — it has NO
/// organization-control semantics. Pass the merge patch as `value`.
///
/// YGN-ORG-01: previously misnamed `realm_organization_update`, which made
/// it look like it bound an organization principal to the Realm. It never
/// did: `ck.realm.update` only patches the Realm object. Organization
/// binding now lives in [`realm_organization_statement`]
/// (`ck.realm.organization`).
pub fn realm_metadata_update(
    realm_id: &str,
    actor: &str,
    value: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let patch = patch_from_value(value)?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::RealmUpdate,
    )
    .target_ref(realm_id)
    .body(object_patch_payload_value(realm_id, patch)?))
}

/// Explicit, externally-sourced authorization for a `ck.realm.organization`
/// statement (YGN-ORG-02).
///
/// The client NEVER signs an organization statement from a human login
/// session: an organization principal is a distinct DID controller. The
/// `proof` (and, for delegated roles, the `delegation_ref`) MUST come back
/// from the organization-side authorization flow (coauth / DID controller /
/// governance service / threshold quorum). This struct is the typed carrier
/// for that result; the builder copies it verbatim into the payload's
/// `authorization` object and does no signing of its own.
#[derive(Clone, Debug)]
pub struct RealmOrganizationAuthorizationInput {
    /// Organization DID or delegated service DID that issued the statement.
    pub issuer: String,
    /// Which kind of principal issued the proof. Delegated roles
    /// (`governance_service` / `account_authority`) MUST carry a
    /// `delegation_ref`; non-delegated roles MUST NOT.
    pub issuer_role: RealmOrganizationIssuerRole,
    /// DID URL of the concrete verification method (bare DIDs are invalid).
    pub verification_method: String,
    /// REQUIRED for delegated roles; MUST resolve to a live organization DID
    /// delegation. MUST be absent for non-delegated roles.
    pub delegation_ref: Option<String>,
    /// Optional human admin / service principal that initiated the decision.
    /// Does NOT become the organization principal.
    pub executed_by: Option<String>,
    /// RFC3339 timestamp of when the organization side signed.
    pub signed_at: chrono::DateTime<chrono::Utc>,
    /// The organization-side signature / threshold transcript / governance
    /// attestation over the canonical statement. Opaque to the client.
    pub proof: SignatureMaterial,
}

/// Build a `ck.realm.organization` statement operation (YGN-ORG-02).
///
/// Constructs the spec-canonical [`RealmOrganizationPayload`] via the SDK
/// strong type — the client never hand-rolls the wire object. Supports both
/// `active` (assert / endorse a relationship) and `revoked` (withdraw a prior
/// statement) via `status`.
///
/// Authorization rule (acceptance criterion): the organization proof is NOT
/// produced from the local human login session. The caller passes an
/// [`RealmOrganizationAuthorizationInput`] obtained from the
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
    organization_did: &str,
    relationship: RealmOrganizationRelationship,
    status: RealmOrganizationStatus,
    control_scopes: Vec<RealmOrganizationControlScope>,
    issued_at: chrono::DateTime<chrono::Utc>,
    authorization: RealmOrganizationAuthorizationInput,
    revokes_statement_id: Option<String>,
) -> anyhow::Result<OperationBuilder> {
    if control_scopes.is_empty() {
        anyhow::bail!("ck.realm.organization control_scopes must not be empty");
    }
    // Local fail-fast on the status / revocation coupling. The same invariant
    // is re-enforced by the SDK verifier server-side; surfacing it here gives
    // the UI an immediate, deterministic error.
    match (status, &revokes_statement_id) {
        (RealmOrganizationStatus::Revoked, None) => {
            anyhow::bail!("ck.realm.organization revoked status requires revokes_statement_id");
        }
        (RealmOrganizationStatus::Active, Some(_)) => {
            anyhow::bail!(
                "ck.realm.organization active status must not carry revokes_statement_id"
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
                "ck.realm.organization issuer_role {:?} requires authorization.delegation_ref",
                authorization.issuer_role
            );
        }
        (false, Some(_)) => {
            anyhow::bail!(
                "ck.realm.organization delegation_ref only valid for delegated issuer_role"
            );
        }
        _ => {}
    }

    let payload = RealmOrganizationPayload {
        statement_id: statement_id.to_owned(),
        realm_id: realm_id_value(realm_id)?,
        organization_id: did_id(organization_did)?,
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
        authorization: RealmOrganizationAuthorization {
            issuer: did_id(&authorization.issuer)?,
            issuer_role: authorization.issuer_role,
            verification_method: authorization.verification_method,
            delegation_ref: authorization.delegation_ref,
            executed_by: authorization
                .executed_by
                .as_deref()
                .map(did_id)
                .transpose()?,
            signed_at: authorization.signed_at,
            proof: authorization.proof,
        },
    };

    let body = serde_json::to_value(&payload)
        .map_err(|err| anyhow::anyhow!("invalid ck.realm.organization payload: {err}"))?;

    Ok(OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::RealmOrganization,
    )
    .target_ref(organization_did)
    .body(body))
}
