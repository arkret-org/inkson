pub(crate) const DEMO_BOARD_SPACE_ID: &str =
    "ak:space:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM";

/// Compact freshness signature for the MLS-unlock axis of the kanban refresh
/// key. Empty when no snapshot has landed and the group epoch floor is still 0
/// (a bare boot before any key material), so on its own it never licenses a
/// refresh; non-empty the moment a snapshot arrives or the epoch advances —
/// exactly the "decryption keys just became available, re-backfill so the
/// pre-join history can finally decrypt" transition. Without this axis an
/// invitee whose MLS snapshot lands AFTER the one-shot bootstrap backfill sees
/// a permanently empty board until a manual page refresh re-runs the backfill
/// with keys already present. (invitee-history-late-decrypt)
pub(crate) fn kanban_mls_unlock_signature(has_snapshot: bool, mls_epoch_floor: u64) -> String {
    if !has_snapshot && mls_epoch_floor == 0 {
        String::new()
    } else {
        format!("snap:{}|ep:{}", has_snapshot as u8, mls_epoch_floor)
    }
}

/// Refresh-key for the kanban live reconciler. `live_epoch` is the per-realm
/// `events/subscribe` engine's monotonic counter ([`crate::realm_events_engine`]):
/// it advances whenever account or Realm sync folds fresh durable events.
/// `account_sync_ready` licenses the initial reconcile but deliberately records
/// only readiness, not the opaque cursor token: the server may re-mint the same
/// frontier with a new token timestamp for an ephemeral-only delta, which is
/// not a Kanban freshness change. `mls_unlock`
/// ([`kanban_mls_unlock_signature`]) is a third axis: sync can be stale exactly
/// while the local MLS snapshot
/// is still being installed, so folding the snapshot/epoch signature in lets a
/// late-arriving Welcome/snapshot re-trigger the backfill+reproject.
pub(crate) fn kanban_projection_refresh_key(
    realm_id: &str,
    account_sync_ready: bool,
    live_epoch: u64,
    mls_unlock: &str,
) -> String {
    format!(
        "{}|{}|{}|{}",
        realm_id.trim(),
        account_sync_ready as u8,
        live_epoch,
        mls_unlock.trim(),
    )
}

pub(crate) fn next_kanban_projection_refresh_key(
    last_seen_key: &str,
    realm_id: &str,
    account_sync_ready: bool,
    live_epoch: u64,
    mls_unlock: &str,
) -> Option<String> {
    let key = kanban_projection_refresh_key(realm_id, account_sync_ready, live_epoch, mls_unlock);
    if last_seen_key == key {
        return None;
    }
    // Refresh when account sync is ready, OR the realm events engine has
    // reported fresh content (`live_epoch > 0`), OR the MLS-unlock axis has
    // progressed (a snapshot/epoch just landed). Any of the three is a real
    // freshness signal; still require a realm selector so a bare boot
    // with none of them doesn't churn.
    let mls_active = !mls_unlock.trim().is_empty();
    if (!account_sync_ready && live_epoch == 0 && !mls_active) || realm_id.trim().is_empty() {
        return None;
    }
    Some(key)
}

pub(crate) fn actor_is_current_account(actor_id: &str, principal_id: &str) -> bool {
    let account = principal_id.trim();
    !account.is_empty() && actor_id.trim() == account
}

pub(crate) const DEMO_STRAND_LEGAL_REVIEW_ID: &str =
    "ak:strand:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz";
pub(crate) const DEMO_STRAND_ONBOARDING_COPY_ID: &str =
    "ak:strand:ASZZoDGudNfXFZynKh4xcEpb5d8kLZQXRpycxlg1qyW-";
pub(crate) const DEMO_STRAND_SECURITY_SIGNOFF_ID: &str =
    "ak:strand:AQmnyvvBmKOWOEOSD2rAYsVBQn6vJ_wdbdUY8CKUGB5c";
pub(crate) const DEMO_STRAND_REVIEW_DISCUSSION_ID: &str =
    "ak:strand:AVBgYTmzSkzTSd1dlFH4ZADaQRkVcx_iTAvXdxlTfxrg";
pub(crate) const DEMO_STRAND_SUPPORT_DISCUSSION_ID: &str =
    "ak:strand:AUiTFJVo328Rc7lc2Le2mjzL_ELZ-uQUn1Fq-C1QNAbh";
pub(crate) const DEMO_STRAND_SECURITY_REVIEW_ID: &str =
    "ak:strand:AVKDZWS92w01isZDuPKuX-DiJymAf0Qcvf0A6qz8Gy-0";
/// Canonical Strand paths whose value carries user content and therefore MUST
/// be encrypted before it leaves the client in an E2EE scope.
///
/// Description lives at top-level `content`; Synthesis lives inside
/// `tracks.synthesis.content`. Each has an `encrypted_content` counterpart.
pub(crate) const KANBAN_PRIVATE_STRAND_PATCH_PATHS: &[&str] = &[
    "content",
    "encrypted_content",
    "tracks.synthesis.content",
    "tracks.synthesis.encrypted_content",
    // The schedule lives under one `calendar` namespace, so the encryptable
    // location is `metadata.fields.calendar.location`.
    "metadata.fields.calendar.location",
];

pub(crate) const KANBAN_DESCRIPTION_PRIVATE_FIELD_PATHS: &[&str] =
    &["content", "encrypted_content"];

pub(crate) const KANBAN_SYNTHESIS_PRIVATE_FIELD_PATHS: &[&str] = &[
    "tracks.synthesis.content",
    "tracks.synthesis.encrypted_content",
];

/// Canonical plaintext path for the Strand Description.
pub(crate) const KANBAN_CONTENT_PATH: &str = "content";

/// Canonical E2EE path for the Strand Description.
pub(crate) const KANBAN_ENCRYPTED_CONTENT_PATH: &str = "encrypted_content";

/// Canonical plaintext path for the Synthesis track body.
pub(crate) const KANBAN_SYNTHESIS_CONTENT_PATH: &str = "tracks.synthesis.content";
/// Canonical E2EE path for the Synthesis track body.
pub(crate) const KANBAN_ENCRYPTED_SYNTHESIS_CONTENT_PATH: &str =
    "tracks.synthesis.encrypted_content";

/// Where a private patch value moves once it has been wrapped in an
/// `EncryptedEnvelope`. Each plaintext/encrypted pair is mutually exclusive,
/// so encryption moves Description from `content` to `encrypted_content` and
/// Synthesis from `tracks.synthesis.content` to
/// `tracks.synthesis.encrypted_content`. Other private metadata paths stay in
/// place.
pub(crate) fn kanban_encrypted_patch_path(path: &str) -> &str {
    if path == KANBAN_CONTENT_PATH {
        KANBAN_ENCRYPTED_CONTENT_PATH
    } else if path == KANBAN_SYNTHESIS_CONTENT_PATH {
        KANBAN_ENCRYPTED_SYNTHESIS_CONTENT_PATH
    } else {
        path
    }
}

pub(crate) const KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE: &str =
    "application/vnd.arkret.strand.patch-value+json";

/// Inline-text ceiling for `ak.content.text` from
/// `strand.schema.json#/$defs/content_block`: longer bodies must move to
/// `ak.content.long_text`, which needs Blob upload the board does not have yet,
/// so the editor refuses the write instead of emitting an invalid ContentBlock.
pub(crate) const KANBAN_CONTENT_TEXT_MAX_CHARS: usize = 262_144;

/// X10.2 — shown for encrypted Strand content this device cannot read yet: no
/// local plaintext sidecar, no suitable MLS Welcome/history material, or a
/// fresh browser before restore. Distinguishes "encrypted, waiting for key
/// material" from genuinely empty content so users don't read it as data loss.
pub(crate) const MLS_LOCKED_FIELD_PLACEHOLDER: &str =
    "🔒 Encrypted — awaiting MLS Welcome or an authorized history source response";

/// Browser-`localStorage` keys for the card-detail panel display
/// preference. Dock mode + width are device-/browser-level UI state
/// (not tied to an account or Space), so they live in `localStorage`
/// on the web build and become no-ops on desktop where there is no
/// browser storage — the session-default applies there instead.
pub(crate) const CARD_DETAIL_DOCKED_STORAGE_KEY: &str = "inkson.card-detail.docked";
pub(crate) const CARD_DETAIL_DOCK_WIDTH_STORAGE_KEY: &str = "inkson.card-detail.dock-width";
pub(crate) const CARD_DETAIL_DOCK_WIDTH_DEFAULT: f64 = 720.0;
pub(crate) const CARD_DETAIL_DOCK_WIDTH_MIN: f64 = 380.0;
pub(crate) const CARD_DETAIL_DOCK_WIDTH_MAX: f64 = 1100.0;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kanban_projection_refresh_ignores_cursor_remints_after_sync_is_ready() {
        let realm_id = "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0";
        let first_key = kanban_projection_refresh_key(realm_id, true, 0, "");

        assert_eq!(
            next_kanban_projection_refresh_key(&first_key, realm_id, true, 0, ""),
            None,
            "a newly signed token for the same ready account frontier is not a durable change"
        );
    }

    #[test]
    fn kanban_projection_refresh_waits_for_a_real_freshness_axis() {
        assert_eq!(
            next_kanban_projection_refresh_key(
                "",
                "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
                false,
                0,
                ""
            ),
            None
        );
        assert_eq!(
            next_kanban_projection_refresh_key("", "", true, 0, ""),
            None
        );
    }

    #[test]
    fn kanban_projection_refresh_fires_on_realm_live_epoch() {
        // Account cursor is still the bootstrap sentinel (the cross-member
        // bug case), but the realm events engine bumped its epoch: the panel
        // must still refresh off that second freshness axis.
        let key = next_kanban_projection_refresh_key(
            "",
            "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            false,
            1,
            "",
        );
        assert_eq!(
            key,
            Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0|0|1|".to_owned())
        );

        // Same epoch + same inputs → no churn.
        assert_eq!(
            next_kanban_projection_refresh_key(
                "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0|0|1|",
                "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
                false,
                1,
                ""
            ),
            None
        );

        // A later epoch advances the key again.
        assert_eq!(
            next_kanban_projection_refresh_key(
                "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0|0|1|",
                "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
                false,
                2,
                ""
            ),
            Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0|0|2|".to_owned())
        );

        // Still no realm/view selector → no refresh even with an epoch.
        assert_eq!(
            next_kanban_projection_refresh_key("", "", false, 5, ""),
            None
        );
    }

    #[test]
    fn kanban_mls_unlock_signature_empty_only_before_any_key_material() {
        // Bare boot: no snapshot, epoch floor 0 → empty, so it cannot on its
        // own license a refresh.
        assert_eq!(kanban_mls_unlock_signature(false, 0), "");
        // A snapshot landing (even at epoch 0) is real progress.
        assert_eq!(kanban_mls_unlock_signature(true, 0), "snap:1|ep:0");
        // An epoch advance is progress even if the presence check races.
        assert_eq!(kanban_mls_unlock_signature(false, 1), "snap:0|ep:1");
        assert_eq!(kanban_mls_unlock_signature(true, 3), "snap:1|ep:3");
    }

    #[test]
    fn kanban_projection_refresh_fires_when_mls_snapshot_lands_late() {
        // The invitee failure mode: account cursor is the bootstrap sentinel
        // and the events engine never advanced (`live_epoch == 0`), so the two
        // existing axes are both stale — yet the local MLS snapshot has just
        // been installed. That transition alone must re-trigger the backfill so
        // the pre-join history can decrypt, instead of waiting for a manual
        // page refresh.
        let before = kanban_mls_unlock_signature(false, 0);
        let boot_key = kanban_projection_refresh_key(
            "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            false,
            0,
            &before,
        );
        assert_eq!(
            next_kanban_projection_refresh_key(
                &boot_key,
                "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
                false,
                0,
                &before
            ),
            None,
            "no cursor, no live epoch, no snapshot → still idle"
        );

        let after = kanban_mls_unlock_signature(true, 1);
        let unlocked = next_kanban_projection_refresh_key(
            &boot_key,
            "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            false,
            0,
            &after,
        );
        assert_eq!(
            unlocked,
            Some(
                "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0|0|0|snap:1|ep:1".to_owned()
            )
        );

        // Same snapshot signature again → no churn.
        assert_eq!(
            next_kanban_projection_refresh_key(
                "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0|0|0|snap:1|ep:1",
                "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
                false,
                0,
                &after,
            ),
            None
        );
    }

    #[test]
    fn actor_is_current_account_requires_exact_non_empty_match() {
        assert!(actor_is_current_account(
            "ak:did_core:web:auth.local.host:users:alice",
            " ak:did_core:web:auth.local.host:users:alice "
        ));
        assert!(!actor_is_current_account(
            "",
            "ak:did_core:web:auth.local.host:users:alice"
        ));
        assert!(!actor_is_current_account(
            "ak:did_core:web:auth.local.host:users:alice",
            ""
        ));
        assert!(!actor_is_current_account(
            "ak:did_core:web:auth.local.host:users:bob",
            "ak:did_core:web:auth.local.host:users:alice"
        ));
    }

    #[test]
    fn mls_locked_placeholder_does_not_blame_recovery_key() {
        assert!(!MLS_LOCKED_FIELD_PLACEHOLDER.contains("24-word"));
        assert!(!MLS_LOCKED_FIELD_PLACEHOLDER.contains("Recovery Key"));
        assert!(MLS_LOCKED_FIELD_PLACEHOLDER.contains("MLS Welcome"));
        assert!(MLS_LOCKED_FIELD_PLACEHOLDER.contains("authorized history source"));
    }
}
