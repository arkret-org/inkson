use super::*;

impl LocalStateStore {
    /// Return the stored remark for `realm_id`, if any. `None` means the
    /// user has not set a local override and the public Realm title
    /// should be rendered.
    pub fn realm_remark(&self, realm_id: &str) -> Option<crate::account_data::RealmRemark> {
        self.load().realm_remarks.get(realm_id).cloned()
    }

    /// All known Realm remarks. The settings UI uses this to render the
    /// edit list; callers MUST NOT publish this map to other Realm
    /// members — it is actor-private per §3.7.
    pub fn realm_remarks(&self) -> BTreeMap<String, crate::account_data::RealmRemark> {
        self.load().realm_remarks
    }

    /// Upsert a remark for `realm_id`. Passing a remark whose
    /// [`RealmRemark::is_empty`] returns true tombstones the entry
    /// (equivalent to `remove_realm_remark`). Persists synchronously to
    /// disk; the caller is responsible for pushing the same payload to
    /// soland via `ak.account_data.set`.
    pub fn set_realm_remark(
        &mut self,
        realm_id: impl Into<String>,
        remark: crate::account_data::RealmRemark,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        if remark.is_empty() {
            self.cached.realm_remarks.remove(&realm_id);
        } else {
            self.cached.realm_remarks.insert(realm_id, remark);
        }
        let _ = self.flush();
    }

    /// Delete the remark for `realm_id`. No-op if none is stored.
    pub fn remove_realm_remark(&mut self, realm_id: &str) {
        self.ensure_cached_loaded();
        self.cached.realm_remarks.remove(realm_id);
        let _ = self.flush();
    }

    // ── Contact remarks (spec client-preferences.md §3.6) ─

    pub fn contact_remark(&self, actor_id: &str) -> Option<crate::account_data::ContactRemark> {
        self.load().contact_remarks.get(actor_id).cloned()
    }

    pub fn contact_remarks(&self) -> BTreeMap<String, crate::account_data::ContactRemark> {
        self.load().contact_remarks
    }

    pub fn set_contact_remark(
        &mut self,
        actor_id: impl Into<String>,
        remark: crate::account_data::ContactRemark,
    ) {
        self.ensure_cached_loaded();
        let actor_id = actor_id.into();
        if remark.is_empty() {
            self.cached.contact_remarks.remove(&actor_id);
        } else {
            self.cached.contact_remarks.insert(actor_id, remark);
        }
        let _ = self.flush();
    }

    pub fn remove_contact_remark(&mut self, actor_id: &str) {
        self.ensure_cached_loaded();
        self.cached.contact_remarks.remove(actor_id);
        let _ = self.flush();
    }

    pub fn display_name_for_actor(&self, actor_id: &str, public_name: &str) -> String {
        match self
            .load()
            .contact_remarks
            .get(actor_id)
            .map(|r| r.display_name(public_name).to_owned())
        {
            Some(name) => name,
            None => public_name.to_owned(),
        }
    }

    // ── Personal blocklist (spec client-preferences.md "ak.account.blocklist") ─

    /// Current personal blocklist. Cheap clone — the underlying `Vec`
    /// is short by design (curated by the user).
    pub fn client_blocklist(&self) -> Vec<crate::account_data::BlocklistEntry> {
        self.load().client_blocklist
    }

    /// True when `did` appears in the local blocklist. Used by the
    /// message renderers to gate message bodies behind a
    /// "Show anyway" affordance.
    pub fn is_user_blocked(&self, did: &str) -> bool {
        crate::account_data::is_blocked(&self.load().client_blocklist, did)
    }

    /// Append `did` to the personal blocklist. Idempotent — duplicate
    /// DIDs are not inserted twice. `reason` is shown back to the user
    /// in Settings → Privacy; pass `None` to skip.
    ///
    /// Persists synchronously to disk; the caller is responsible for
    /// pushing the new list to soland via
    /// `ak.account_data.set("ak.account.blocklist", …)`.
    pub fn block_user(&mut self, did: impl AsRef<str>, reason: Option<String>) -> bool {
        self.ensure_cached_loaded();
        let now = arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now());
        let changed = crate::account_data::block_user_in(
            &mut self.cached.client_blocklist,
            did.as_ref(),
            reason,
            Some(now),
        );
        if changed {
            let _ = self.flush();
        }
        changed
    }

    /// Remove every entry for `did` from the personal blocklist.
    /// Returns `true` when at least one entry was removed.
    pub fn unblock_user(&mut self, did: impl AsRef<str>) -> bool {
        self.ensure_cached_loaded();
        let changed =
            crate::account_data::unblock_user_in(&mut self.cached.client_blocklist, did.as_ref());
        if changed {
            let _ = self.flush();
        }
        changed
    }

    /// Append a typed block (`kind` ∈ actor / service / domain / organization)
    /// to the personal blocklist. Idempotent per `(kind, value)` pair.
    /// `applies_to` lists the surfaces the block covers (empty = all default
    /// surfaces); `expires_at` is an optional RFC 3339 expiry. Same
    /// persistence + push contract as [`block_user`].
    pub fn block_target(
        &mut self,
        kind: impl AsRef<str>,
        value: impl AsRef<str>,
        reason: Option<String>,
        applies_to: Vec<String>,
        expires_at: Option<String>,
    ) -> bool {
        self.ensure_cached_loaded();
        let now = arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now());
        let changed = crate::account_data::block_target_in(
            &mut self.cached.client_blocklist,
            kind.as_ref(),
            value.as_ref(),
            reason,
            applies_to,
            expires_at,
            Some(now),
        );
        if changed {
            let _ = self.flush();
        }
        changed
    }

    /// Remove the `(kind, value)` block from the personal blocklist. Returns
    /// `true` when an entry was removed. Prefer this over [`unblock_user`] on
    /// surfaces that track the target kind.
    pub fn unblock_target(&mut self, kind: impl AsRef<str>, value: impl AsRef<str>) -> bool {
        self.ensure_cached_loaded();
        let changed = crate::account_data::unblock_target_in(
            &mut self.cached.client_blocklist,
            kind.as_ref(),
            value.as_ref(),
        );
        if changed {
            let _ = self.flush();
        }
        changed
    }

    /// Replace the whole personal blocklist from `/sync account_data`.
    /// User edits still go through [`block_user`] / [`unblock_user`];
    /// this method is only for remote state hydration.
    pub fn set_client_blocklist(&mut self, entries: Vec<crate::account_data::BlocklistEntry>) {
        self.ensure_cached_loaded();
        self.cached.client_blocklist = entries;
        let _ = self.flush();
    }

    /// Best-effort name for `realm_id`: trimmed `local_name` from the
    /// stored remark if set, otherwise `public_title`. Mirrors the §3.7
    /// "UI MUST prefer local_name" rule so the sidebar / dashboard /
    /// dashboard cards all agree.
    pub fn display_name_for_realm(&self, realm_id: &str, public_title: &str) -> String {
        match self
            .load()
            .realm_remarks
            .get(realm_id)
            .map(|r| r.display_name(public_title).to_owned())
        {
            Some(name) => name,
            None => public_title.to_owned(),
        }
    }

    /// Get the latest Seal view for a Realm. Returns the Default view
    /// (empty frontier / empty leaves / no state_root) when none has been
    /// observed yet — Move builders treat that as "use sha256(empty)
    /// sentinel".
    pub fn seal_view_for_realm(&self, realm_id: &str) -> LocalSealView {
        self.load()
            .seal_views
            .get(realm_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Replace the Seal view snapshot for a Realm. Called from the sync
    /// path once the `/sync` response surfaces the projection's Seal
    /// view. Tests use this to seed Move-frontier behavior.
    pub fn set_realm_seal_view(&mut self, realm_id: impl Into<String>, view: LocalSealView) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        if self.cached.seal_views.get(&realm_id) == Some(&view) {
            return; // seal view unchanged — skip flush
        }
        let accepted_heads = view
            .frontier
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        self.cached.mls_governance_proofs.retain(|_, entry| {
            entry.request.realm_id.as_str() != realm_id
                || accepted_heads.contains(entry.accepted_seal_id.as_str())
        });
        self.cached.seal_views.insert(realm_id, view);
        let _ = self.flush();
    }

    /// All known Seal views — handy for app-wide UI banners.
    pub fn seal_views(&self) -> BTreeMap<String, LocalSealView> {
        self.load().seal_views
    }

    /// Convenience: pick the right `seal_ref` to thread into a Move
    /// builder for a given Realm. Returns the lex-min frontier head when
    /// available, otherwise the `sha256(empty)` sentinel. Mirrors
    /// [`LocalSealView::move_seal_ref`].
    pub fn seal_ref_for_realm_move(&self, realm_id: &str) -> String {
        self.seal_view_for_realm(realm_id).move_seal_ref()
    }
}
