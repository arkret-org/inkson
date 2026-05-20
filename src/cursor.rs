//! Cursor types are owned by the Contrix Rust SDK.
//!
//! Round R2/R3 (T03): the SDK now exposes
//! [`contrix_sdk::cursor::generate_cursor_handle`] which yields a
//! ≥22-character base64url handle (≥128 bits of entropy). Any client-side
//! caller that previously hand-rolled an `h` field MUST switch to that
//! helper so the minimum-length floor stays enforced.

pub use contrix_sdk::cursor::{
    CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, CursorTarget, SpacePosition, SyncPositions,
    SyncTracker, generate_cursor_handle,
};
