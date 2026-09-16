//! Principal-Control Realm authoring classification.
//!
//! A PCR genesis is authored by a delegated controller on behalf of the Agent
//! account it manages. The distinction matters at the submit boundary: an Agent
//! PCR genesis is a basis-free create whose executor is its controller, so it
//! never carries the founding-unit context an ordinary Realm bootstrap does.

/// A Control Event in an Agent's own PCR, authored by its delegated controller.
fn is_agent_pcr_control(event: &arkret_sdk::Event) -> bool {
    let Some(executor) = event.executed_by.as_ref() else {
        return false;
    };
    let Some((controller, fragment)) = event
        .authorization_ref
        .as_ref()
        .and_then(|reference| reference.as_str().rsplit_once('#'))
    else {
        return false;
    };
    if executor == &event.actor_id || fragment != "managed-controller" {
        return false;
    }
    arkret_sdk::Did::new(controller.to_owned())
        .ok()
        .and_then(|did| arkret_sdk::project_did_to_core_id(&did).ok())
        .is_some_and(|core_id| core_id == *event.actor_id.signing_principal_id())
}

/// The `ak.realm.create` that opens an Agent's PCR.
pub(crate) fn is_agent_pcr_genesis(event: &arkret_sdk::Event) -> bool {
    event.kind == arkret_sdk::EventKind::RealmCreate && is_agent_pcr_control(event)
}
