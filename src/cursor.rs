//! Cursor types are owned by the Contrix Rust SDK.
//!
//! Round R2/R3 (T03): the SDK now exposes
//! [`contrix_sdk::cursor::generate_cursor_handle`] which yields a
//! ≥22-character base64url handle (≥128 bits of entropy). Any client-side
//! caller that previously hand-rolled an `h` field MUST switch to that
//! helper so the minimum-length floor stays enforced.
//!
//! P3B.9.2: re-export `SpacePosition` and add the small UI-facing
//! helpers ([`flow_position_label`], [`flow_position_hlc`]) that consume
//! the new Flow position projection fields shipped on `contrix-service-api`.
//! UI callers (kanban move arrow, timeline scroll-to-position) should
//! prefer these over decoding the raw JSON.

pub use contrix_sdk::cursor::{
    CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, CursorTarget, SpacePosition, SyncPositions,
    SyncTracker, generate_cursor_handle,
};

/// Compact label for a [`SpacePosition`] used by the timeline jump-to
/// indicator and the kanban move arrow. Returns a string of the form
/// `"@<hlc-short> ⇢ <frontier-count> tips"`.
///
/// `TODO(circle-rollout-P3B.9.2):` once the new spec projection field
/// `last_read_at` lands on `SpacePosition`, surface it here so the
/// label can read `"… · last read 2m ago"`. The field is registered
/// in `contrix-service-api/openapi.yaml` but the SDK reducer projection
/// hasn't promoted it yet.
pub fn flow_position_label(position: &SpacePosition) -> String {
    // HLC format is `<rfc3339>-<seq>`. We strip the trailing `-<seq>`
    // chunk so the label fits in a chip; if there's no hyphen at all
    // (legacy / future format) we fall back to the full value.
    let short = position
        .order
        .rsplit_once('-')
        .map(|(left, _)| left)
        .unwrap_or(position.order.as_str());
    format!("@{} ⇢ {} tip(s)", short, position.p.len())
}

/// Best-effort HLC extractor — returns the `order` field directly. The
/// renamed projection field in the new spec is `hlc` (vs `order`); the
/// SDK still serialises it as `o`, so the field on the struct stays
/// `order` for now. Callers should use this helper rather than touching
/// `position.order` so the rename lands in a single place when it
/// arrives in the SDK.
pub fn flow_position_hlc(position: &SpacePosition) -> &str {
    position.order.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_position() -> SpacePosition {
        SpacePosition {
            p: vec!["cx:event:tip-1".to_owned(), "cx:event:tip-2".to_owned()],
            order: "2026-05-26T00:00:00Z-0001".to_owned(),
            h: "sha256:abcd".to_owned(),
        }
    }

    #[test]
    fn label_reports_hlc_and_tip_count() {
        let label = flow_position_label(&sample_position());
        assert!(label.starts_with("@2026-05-26T00:00:00Z"));
        assert!(label.contains("2 tip(s)"));
    }

    #[test]
    fn hlc_returns_order_field() {
        let position = sample_position();
        assert_eq!(flow_position_hlc(&position), "2026-05-26T00:00:00Z-0001");
    }
}
