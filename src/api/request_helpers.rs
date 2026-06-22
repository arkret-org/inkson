//! Request-body builders for the directory resolve-handle surface. Structural
//! move out of `api/mod.rs` with no logic change; the functions stay
//! `pub(crate)` so the `directory` sibling module and the test module reach
//! them through `super::*`.

use super::*;

pub(crate) fn resolve_handle_request_body(
    handle: &str,
    context: ResolveHandleContext<'_>,
) -> anyhow::Result<cokret_sdk::models::DirectoryResolveHandleRequestBody> {
    let non_empty = |value: Option<&str>| {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    };
    let realm_id = match non_empty(context.realm_id) {
        Some(realm_id) => Some(
            cokret_sdk::RealmId::new(&realm_id)
                .map_err(|err| anyhow::anyhow!("invalid realm_id `{realm_id}`: {err}"))?,
        ),
        None => None,
    };
    let expected_did = match non_empty(context.expected_did) {
        Some(did) => Some(
            cokret_sdk::Did::new(did.clone())
                .map_err(|err| anyhow::anyhow!("invalid expected_did `{did}`: {err}"))?,
        ),
        None => None,
    };
    let requester = match non_empty(context.requester) {
        Some(did) => Some(
            cokret_sdk::Did::new(did.clone())
                .map_err(|err| anyhow::anyhow!("invalid requester `{did}`: {err}"))?,
        ),
        None => None,
    };
    let intent = match non_empty(context.intent) {
        Some(intent) => Some(
            intent
                .parse::<cokret_sdk::models::DirectoryIntent>()
                .map_err(|err| anyhow::anyhow!("invalid directory intent `{intent}`: {err}"))?,
        ),
        None => None,
    };
    Ok(cokret_sdk::models::DirectoryResolveHandleRequestBody {
        handle: handle.to_owned(),
        expected_did,
        proof_challenge: non_empty(context.proof_challenge),
        claim_presentations: Vec::new(),
        intent,
        requester,
        audience: non_empty(context.audience),
        realm_id,
        proofs: context
            .proofs
            .iter()
            .map(|proof| proof.trim())
            .filter(|proof| !proof.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
    })
}

pub(crate) fn canonical_invitee_handle(target: &str) -> anyhow::Result<String> {
    parse_user_handle(target)
        .map(|handle| handle.handle)
        .ok_or_else(|| {
            anyhow::anyhow!("invitee must be a DID or canonical handle `<localpart>:<domain>`")
        })
}
