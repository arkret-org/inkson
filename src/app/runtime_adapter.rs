//! Host adapters use the domain runtime's closure-based input contracts.
/// Capture a live host once. Fixture callers outside the application continue
/// to attach their explicitly supplied StateStoreHandle on EventSubmitter.
pub(crate) fn event_submitter(
    http: arkret_sdk::http_client::Client,
) -> crate::event_submit::EventSubmitter {
    let submitter = crate::event_submit::EventSubmitter::new(http);
    match crate::presentation::current_context() {
        Some(context) => submitter.with_state_store(context.state_store.handle()),
        None => submitter,
    }
}
