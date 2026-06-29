pub(crate) const DEMO_BOARD_SPACE_ID: &str = "ck:space:0196419b-0000-7000-8000-00000000b0a0";

/// Maximum number of times a CAS-conflicted Move is automatically
/// rebased + re-submitted before the UI surfaces it as Quarantined and
/// requires manual review. Three is enough to absorb typical
/// two-actor races without spinning indefinitely if the cell is hot.
pub(crate) const MAX_CONFLICT_REBASE_ATTEMPTS: u8 = 3;

/// Refresh-key for the kanban live reconciler. `live_epoch` is the per-realm
/// `events/subscribe` engine's monotonic counter ([`crate::realm_events_engine`]):
/// it advances when that engine folds fresh realm events that the
/// (cross-member-lossy) account `sync_cursor` never delivered, giving the panel
/// a second, correct freshness axis besides the account cursor.
pub(crate) fn kanban_projection_refresh_key(
    realm_id: &str,
    view_id: &str,
    sync_cursor: &str,
    live_epoch: u64,
) -> String {
    format!(
        "{}|{}|{}|{}",
        realm_id.trim(),
        view_id.trim(),
        sync_cursor.trim(),
        live_epoch
    )
}

pub(crate) fn next_kanban_projection_refresh_key(
    last_seen_key: &str,
    realm_id: &str,
    view_id: &str,
    sync_cursor: &str,
    live_epoch: u64,
) -> Option<String> {
    let key = kanban_projection_refresh_key(realm_id, view_id, sync_cursor, live_epoch);
    if last_seen_key == key {
        return None;
    }
    let cursor = sync_cursor.trim();
    // Refresh when the account cursor is usable OR the realm events engine has
    // reported fresh content (`live_epoch > 0`). Either way still require a
    // realm / view selector so a bare boot doesn't churn.
    let has_usable_cursor = !(cursor.is_empty() || cursor == "-");
    if (!has_usable_cursor && live_epoch == 0)
        || (realm_id.trim().is_empty() && view_id.trim().is_empty())
    {
        return None;
    }
    Some(key)
}

pub(crate) fn actor_is_current_account(actor_id: &str, account_did: &str) -> bool {
    let account = account_did.trim();
    !account.is_empty() && actor_id.trim() == account
}

pub(crate) const DEMO_STRAND_LEGAL_REVIEW_ID: &str =
    "ck:strand:0196419b-0000-7000-8000-000000000101";
pub(crate) const DEMO_STRAND_ONBOARDING_COPY_ID: &str =
    "ck:strand:0196419b-0000-7000-8000-000000000102";
pub(crate) const DEMO_STRAND_SECURITY_SIGNOFF_ID: &str =
    "ck:strand:0196419b-0000-7000-8000-000000000103";
pub(crate) const DEMO_STRAND_REVIEW_DISCUSSION_ID: &str =
    "ck:strand:0196419b-0000-7000-8000-000000000201";
pub(crate) const DEMO_STRAND_SUPPORT_DISCUSSION_ID: &str =
    "ck:strand:0196419b-0000-7000-8000-000000000202";
pub(crate) const DEMO_STRAND_SECURITY_REVIEW_ID: &str =
    "ck:strand:0196419b-0000-7000-8000-000000000203";
pub(crate) const KANBAN_PRIVATE_STRAND_PATCH_PATHS: &[&str] = &[
    "body",
    "synthesis",
    "content",
    "attachments",
    "fields.body",
    "fields.synthesis",
    "metadata.fields.location",
    "fields.location",
    "tracks.synthesis.body",
    "tracks.discussion.body",
];
pub(crate) const KANBAN_BODY_PRIVATE_FIELD_PATHS: &[&str] = &["body", "fields.body"];
pub(crate) const KANBAN_SYNTHESIS_PRIVATE_FIELD_PATHS: &[&str] =
    &["synthesis", "fields.synthesis", "tracks.synthesis.body"];
pub(crate) const KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE: &str =
    "application/vnd.cokret.strand.patch-value+json";

/// X10.2 — shown for an encrypted private field (body/synthesis) that this
/// device cannot read yet: no local plaintext sidecar, no suitable MLS
/// Welcome/history material, or a fresh browser before restore. Distinguishes
/// "encrypted, waiting for key material" from genuinely empty content so users
/// don't read it as data loss.
pub(crate) const MLS_LOCKED_FIELD_PLACEHOLDER: &str =
    "🔒 Encrypted — waiting for MLS Welcome or shared history key";

/// Browser-`localStorage` keys for the card-detail panel display
/// preference. Dock mode + width are device-/browser-level UI state
/// (not tied to an account or Space), so they live in `localStorage`
/// on the web build and become no-ops on desktop where there is no
/// browser storage — the session-default applies there instead.
pub(crate) const CARD_DETAIL_DOCKED_STORAGE_KEY: &str = "yougen.card-detail.docked";
pub(crate) const CARD_DETAIL_DOCK_WIDTH_STORAGE_KEY: &str = "yougen.card-detail.dock-width";
pub(crate) const CARD_DETAIL_DOCK_WIDTH_DEFAULT: f64 = 720.0;
pub(crate) const CARD_DETAIL_DOCK_WIDTH_MIN: f64 = 380.0;
pub(crate) const CARD_DETAIL_DOCK_WIDTH_MAX: f64 = 1100.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kanban_projection_refresh_waits_for_cursor_advance() {
        let first_key = kanban_projection_refresh_key(" ck:realm:r1 ", "", " ck:cursor:1 ", 0);

        assert_eq!(
            next_kanban_projection_refresh_key(&first_key, "ck:realm:r1", "", "ck:cursor:1", 0),
            None
        );
        assert_eq!(
            next_kanban_projection_refresh_key(&first_key, "ck:realm:r1", "", "ck:cursor:2", 0),
            Some("ck:realm:r1||ck:cursor:2|0".to_owned())
        );
    }

    #[test]
    fn kanban_projection_refresh_ignores_empty_or_bootstrap_cursor() {
        assert_eq!(
            next_kanban_projection_refresh_key("", "ck:realm:r1", "", "", 0),
            None
        );
        assert_eq!(
            next_kanban_projection_refresh_key("", "ck:realm:r1", "", "-", 0),
            None
        );
        assert_eq!(
            next_kanban_projection_refresh_key("", "", "", "ck:cursor:1", 0),
            None
        );
    }

    #[test]
    fn kanban_projection_refresh_fires_on_realm_live_epoch() {
        // Account cursor is still the bootstrap sentinel (the cross-member
        // bug case), but the realm events engine bumped its epoch: the panel
        // must still refresh off that second freshness axis.
        let key = next_kanban_projection_refresh_key("", "ck:realm:r1", "", "-", 1);
        assert_eq!(key, Some("ck:realm:r1||-|1".to_owned()));

        // Same epoch + same inputs → no churn.
        assert_eq!(
            next_kanban_projection_refresh_key(
                "ck:realm:r1||-|1",
                "ck:realm:r1",
                "",
                "-",
                1
            ),
            None
        );

        // A later epoch advances the key again.
        assert_eq!(
            next_kanban_projection_refresh_key(
                "ck:realm:r1||-|1",
                "ck:realm:r1",
                "",
                "-",
                2
            ),
            Some("ck:realm:r1||-|2".to_owned())
        );

        // Still no realm/view selector → no refresh even with an epoch.
        assert_eq!(
            next_kanban_projection_refresh_key("", "", "", "-", 5),
            None
        );
    }

    #[test]
    fn actor_is_current_account_requires_exact_non_empty_match() {
        assert!(actor_is_current_account(
            "did:web:auth.local.host:users:alice",
            " did:web:auth.local.host:users:alice "
        ));
        assert!(!actor_is_current_account(
            "",
            "did:web:auth.local.host:users:alice"
        ));
        assert!(!actor_is_current_account(
            "did:web:auth.local.host:users:alice",
            ""
        ));
        assert!(!actor_is_current_account(
            "did:web:auth.local.host:users:bob",
            "did:web:auth.local.host:users:alice"
        ));
    }

    #[test]
    fn mls_locked_placeholder_does_not_blame_recovery_key() {
        assert!(!MLS_LOCKED_FIELD_PLACEHOLDER.contains("24-word"));
        assert!(!MLS_LOCKED_FIELD_PLACEHOLDER.contains("Recovery Key"));
        assert!(MLS_LOCKED_FIELD_PLACEHOLDER.contains("MLS Welcome"));
        assert!(MLS_LOCKED_FIELD_PLACEHOLDER.contains("history key"));
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn local_storage_get(key: &str) -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()
        .flatten()?
        .get_item(key)
        .ok()
        .flatten()
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn local_storage_set(key: &str, value: &str) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(key, value);
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn local_storage_get(_key: &str) -> Option<String> {
    None
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn local_storage_set(_key: &str, _value: &str) {}

/// Hydrate the docked-vs-dialog choice from `localStorage`. Defaults to
/// the centered dialog when unset or on desktop.
pub(crate) fn read_card_detail_docked() -> bool {
    local_storage_get(CARD_DETAIL_DOCKED_STORAGE_KEY)
        .map(|value| value == "true")
        .unwrap_or(false)
}

/// Hydrate the docked-panel width from `localStorage`, clamped to the
/// same bounds the drag handle enforces. Falls back to the default when
/// unset, unparseable, or on desktop.
pub(crate) fn read_card_detail_dock_width() -> f64 {
    local_storage_get(CARD_DETAIL_DOCK_WIDTH_STORAGE_KEY)
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|width| width.is_finite())
        .map(|width| width.clamp(CARD_DETAIL_DOCK_WIDTH_MIN, CARD_DETAIL_DOCK_WIDTH_MAX))
        .unwrap_or(CARD_DETAIL_DOCK_WIDTH_DEFAULT)
}

pub(crate) fn persist_card_detail_docked(docked: bool) {
    local_storage_set(
        CARD_DETAIL_DOCKED_STORAGE_KEY,
        if docked { "true" } else { "false" },
    );
}

pub(crate) fn persist_card_detail_dock_width(width: f64) {
    local_storage_set(CARD_DETAIL_DOCK_WIDTH_STORAGE_KEY, &format!("{width:.0}"));
}
