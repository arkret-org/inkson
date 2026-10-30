use crate::browser_storage::{local_storage_get, local_storage_set};

pub(crate) const DEMO_BOARD_SPACE_ID: &str =
    "ak:space:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM";

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
