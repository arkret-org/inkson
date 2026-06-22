//! Cursor types are owned by the Cokret Rust SDK.
//!
//! Round R2/R3 (T03): the SDK now exposes
//! [`cokret_sdk::cursor::generate_cursor_handle`] which yields a
//! ≥22-character base64url handle (≥128 bits of entropy). Any client-side
//! caller that previously hand-rolled an `h` field MUST switch to that
//! helper so the minimum-length floor stays enforced.
//!
//! P3B.9.2: re-export the SDK realm sync position and add the small UI-facing
//! helpers ([`strand_position_label`], [`strand_position_hlc`]) that consume
//! the new Strand position projection fields shipped on `cokret-service-api`.
//! UI callers (kanban move arrow, message position chips) should
//! prefer these over decoding the raw JSON.

pub use cokret_sdk::cursor::{
    CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, RealmSyncPosition as RealmPosition,
    SyncPositions, SyncTracker, generate_cursor_handle,
};

/// Compact label for a [`RealmPosition`] used by Board move controls and
/// message position chips. Returns a string of the form
/// `"@<hlc-short> ⇢ <frontier-count> tip(s)"`, optionally suffixed
/// with a middle-dot separator before `last read <rfc3339>` when the caller supplies the
/// `last_read_at` value.
///
/// `last_read_at` is sourced from the raw account-subscribe projection
/// for now (the SDK's realm position struct has no field for it yet —
/// when the SDK promotes the field, callers should switch to reading
/// it directly off the struct and pass the value in here).
pub fn strand_position_label(position: &RealmPosition, last_read_at: Option<&str>) -> String {
    // HLC format is `<rfc3339>-<seq>`. We strip the trailing `-<seq>`
    // chunk so the label fits in a chip; if there's no hyphen at all
    // we fall back to the full value.
    let short = position
        .timeline_order
        .rsplit_once('-')
        .map(|(left, _)| left)
        .unwrap_or(position.timeline_order.as_str());
    let core = format!("@{} ⇢ {} tip(s)", short, position.frontier.len());
    match last_read_at
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(ts) => format!("{core} · last read {ts}"),
        None => core,
    }
}

/// Extract the optional `last_read_at` timestamp from the raw account
/// subscribe Space-position JSON. Returns `None` when the field is
/// absent or non-string (older soland builds / SDK projections).
///
/// Spec field name registered on `cokret-service-api/openapi.yaml`.
/// Once the SDK promotes it onto [`RealmPosition`] directly, replace the JSON
/// lookup with a struct field read.
pub fn last_read_at_from_projection(raw: &serde_json::Value) -> Option<String> {
    raw.get("last_read_at")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// Best-effort HLC extractor — returns the `order` field directly. The
/// renamed projection field in the new spec is `hlc` (vs `order`); the
/// SDK cursor position model now stores it as `timeline_order`. Callers should
/// use this helper rather than touching the struct field directly so the rename
/// lands in a single place when it arrives in the SDK.
pub fn strand_position_hlc(position: &RealmPosition) -> &str {
    position.timeline_order.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_position() -> RealmPosition {
        RealmPosition {
            frontier: vec!["ck:event:tip-1".to_owned(), "ck:event:tip-2".to_owned()],
            timeline_order: "2026-05-26T00:00:00Z-0001".to_owned(),
            state_digest: "sha256:abcd".to_owned(),
        }
    }

    #[test]
    fn label_reports_hlc_and_tip_count() {
        let label = strand_position_label(&sample_position(), None);
        assert!(label.starts_with("@2026-05-26T00:00:00Z"));
        assert!(label.contains("2 tip(s)"));
        assert!(!label.contains("last read"));
    }

    #[test]
    fn label_appends_last_read_when_provided() {
        let label = strand_position_label(&sample_position(), Some("2026-05-26T00:05:00Z"));
        assert!(label.contains("last read 2026-05-26T00:05:00Z"));
    }

    #[test]
    fn label_ignores_blank_last_read() {
        let label = strand_position_label(&sample_position(), Some("   "));
        assert!(!label.contains("last read"));
    }

    #[test]
    fn hlc_returns_order_field() {
        let position = sample_position();
        assert_eq!(strand_position_hlc(&position), "2026-05-26T00:00:00Z-0001");
    }

    #[test]
    fn last_read_extractor_reads_optional_field() {
        let raw = serde_json::json!({
            "last_read_at": "2026-05-26T00:05:00Z"
        });
        assert_eq!(
            last_read_at_from_projection(&raw).as_deref(),
            Some("2026-05-26T00:05:00Z")
        );

        let empty = serde_json::json!({});
        assert!(last_read_at_from_projection(&empty).is_none());

        let blank = serde_json::json!({ "last_read_at": "  " });
        assert!(last_read_at_from_projection(&blank).is_none());
    }
}
