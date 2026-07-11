//! Request-body helpers for directory resolve-handle flows.

use crate::identity::handle::parse_user_handle;

/// Context for `ak.find.directory.query.resolve_handle`.
///
/// Protocol distinction: `lookup` / `mention` are display-safe resolves;
/// `member_add` / `invite` request Realm/audience-bound membership-builder
/// material. Callers that are about to invite or add a member MUST provide
/// `intent`, `requester`, `realm_id`, and `audience`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ResolveHandleContext<'a> {
    pub(crate) intent: Option<&'a str>,
    pub(crate) requester: Option<&'a str>,
    pub(crate) audience: Option<&'a str>,
    pub(crate) realm_id: Option<&'a str>,
    pub(crate) expected_did: Option<&'a str>,
    pub(crate) proof_challenge: Option<&'a str>,
    pub(crate) proofs: &'a [&'a str],
}

pub(crate) fn resolve_handle_request_body(
    handle: &str,
    context: ResolveHandleContext<'_>,
) -> anyhow::Result<arkret_sdk::models::DirectoryResolveHandleRequestBody> {
    let non_empty = |value: Option<&str>| {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    };
    let realm_id = match non_empty(context.realm_id) {
        Some(realm_id) => Some(
            arkret_sdk::RealmId::new(&realm_id)
                .map_err(|err| anyhow::anyhow!("invalid realm_id `{realm_id}`: {err}"))?,
        ),
        None => None,
    };
    let expected_did = match non_empty(context.expected_did) {
        Some(did) => Some(
            arkret_sdk::Did::new(did.clone())
                .map_err(|err| anyhow::anyhow!("invalid expected_did `{did}`: {err}"))?,
        ),
        None => None,
    };
    let requester = match non_empty(context.requester) {
        Some(did) => Some(
            arkret_sdk::Did::new(did.clone())
                .map_err(|err| anyhow::anyhow!("invalid requester `{did}`: {err}"))?,
        ),
        None => None,
    };
    let intent = match non_empty(context.intent) {
        Some(intent) => Some(
            intent
                .parse::<arkret_sdk::models::DirectoryIntent>()
                .map_err(|err| anyhow::anyhow!("invalid directory intent `{intent}`: {err}"))?,
        ),
        None => None,
    };
    Ok(arkret_sdk::models::DirectoryResolveHandleRequestBody {
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
