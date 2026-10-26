//! Explicit contact projection handle.
/// Current account's contact inbox, shared by the sidebar and notifications.
#[derive(Clone, Copy)]
pub(crate) struct ContactInbox(pub glory::Cage<Vec<crate::models::ContactView>>);

impl ContactInbox {
    pub(crate) fn pending_count(self, snapshot: &crate::state::ClientLocalState) -> usize {
        self.0
            .get()
            .iter()
            .filter(|row| row.state == arkret_sdk::ContactState::PendingIncoming)
            .filter(|row| {
                !crate::account_data::suppresses_contact_attention(
                    &snapshot.client_blocklist,
                    &row.peer.contact_actor_id(),
                )
            })
            .count()
    }

    pub(crate) fn visible_pending(
        self,
        snapshot: &crate::state::ClientLocalState,
    ) -> Vec<crate::models::ContactView> {
        self.0
            .get()
            .iter()
            .filter(|row| row.state == arkret_sdk::ContactState::PendingIncoming)
            .filter(|row| {
                !crate::account_data::hides_contact_request(
                    &snapshot.client_blocklist,
                    &row.peer.contact_actor_id(),
                )
            })
            .cloned()
            .collect()
    }
}
