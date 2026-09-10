pub(crate) mod account_auth;
pub(crate) mod active_account;
pub(crate) mod agent_signer_evidence;
pub(crate) mod authoring_generation;
pub(crate) mod device_directory;
pub(crate) mod device_name;
pub(crate) mod device_pairing;
pub(crate) mod did_key;
pub(crate) mod handle;
pub(crate) mod history;
pub(crate) mod identity_abandonment;
pub(crate) mod member_identity_store;
pub(crate) mod principal_control;
pub(crate) mod principal_genesis;
pub(crate) mod principal_registration;
pub(crate) mod session_refresh;

/// The controller portion of a DID URL verification method.
///
/// Strips a `?query` and then a `#fragment`, leaving the identifier that
/// authored the proof. Deliberately **not** the SDK's
/// `arkret_sdk::verification_method_did`: that one validates the result as a
/// `Did`, while this client's callers hand the output to
/// `mls_api_helpers::principal_core_id`, which also accepts the
/// `ak:did_core:` core-id spelling. Swapping in the stricter SDK parser would
/// silently reject that form, so any move to it has to re-verify every caller
/// first.
pub(crate) fn verification_method_controller(verification_method: &str) -> &str {
    let no_query = verification_method
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(verification_method);
    no_query
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(no_query)
}
