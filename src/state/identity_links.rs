use super::*;

fn identity_link_cache_key(realm_id: &str, group_id: &str, epoch: u64, leaf_index: u64) -> String {
    format!("{realm_id}\u{1f}{group_id}\u{1f}{epoch}\u{1f}{leaf_index}")
}

impl LocalStateStore {
    pub(crate) fn locally_authenticated_identity_link(
        &self,
        realm_id: &arkret_sdk::RealmId,
        group_id: &str,
        epoch: u64,
        leaf_index: u64,
    ) -> Option<LocallyAuthenticatedIdentityLink> {
        let key = identity_link_cache_key(realm_id.as_str(), group_id, epoch, leaf_index);
        self.with_mls_receive_fields(|state, overlay| {
            overlay
                .identity_links
                .get(&key)
                .or_else(|| state.authenticated_identity_links.get(&key))
                .cloned()
        })
    }

    pub(crate) fn cache_locally_authenticated_identity_link(
        &self,
        entry: LocallyAuthenticatedIdentityLink,
    ) -> anyhow::Result<()> {
        let key =
            identity_link_cache_key(
                entry.identity_link.realm_id.as_str(),
                entry.identity_link.mls_group_id.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("IdentityLink lacks its authenticated MLS group")
                })?,
                entry.identity_link.mls_epoch,
                entry.identity_link.mls_leaf_index,
            );
        if let Some(existing) = self.load().authenticated_identity_links.get(&key) {
            if existing != &entry {
                anyhow::bail!(
                    "authenticated IdentityLink coordinate resolves to conflicting exact bytes"
                );
            }
            return Ok(());
        }
        let mut overlay = self.lock_mls_receive_overlay();
        if let Some(existing) = overlay.identity_links.get(&key) {
            if existing != &entry {
                anyhow::bail!(
                    "authenticated IdentityLink coordinate resolves to conflicting exact bytes"
                );
            }
            return Ok(());
        }
        overlay.identity_links.insert(key, entry);
        drop(overlay);
        self.persist_e2ee_plaintext_cache_if_ready();
        Ok(())
    }
}
