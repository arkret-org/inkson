use std::sync::LazyLock;

pub use arkret_sdk::{
    AccountSubscribeFolder, AccountSubscribeReconnectAfter, AccountSubscribeSnapshotResult,
};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::models::ClientSyncOutcome;

/// Keep account-subscribe network calls globally serial so duplicate UI tasks
/// cannot leave multiple pending long-polls in browser runtimes.
pub(crate) static ACCOUNT_SUBSCRIBE_NETWORK_GATE: LazyLock<Mutex<()>> =
    LazyLock::new(|| Mutex::new(()));

/// Maximum bytes any native NDJSON streaming reader will buffer between two
/// newline delimiters. A spec-compliant server delimits every frame with `\n`;
/// a faulty / malicious server that keeps pushing bytes without a delimiter (or
/// a single oversized frame) would otherwise grow the `pending` buffer without
/// bound until the client OOMs. Frames are small control / delta envelopes;
/// 16 MiB is far above any legitimate single frame yet caps the OOM vector.
/// Shared by BOTH NDJSON stream paths (`account.subscribe` and
/// `events.subscribe`) so the resource bound lives in exactly one place.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const MAX_NDJSON_STREAM_FRAME_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn new_account_subscribe_folder() -> AccountSubscribeFolder {
    // The SDK folder is now explicitly bound to request trace context rather
    // than implementing `Default`.  Parsers receive a complete body/stream
    // without the original request, so use the same catch-up context Inkson
    // sends for account bootstrap snapshots.
    AccountSubscribeFolder::for_request(&arkret_sdk::SyncRequestBody {
        after: None,
        catchup: Some(true),
        filter: None,
        subscriptions: None,
        wait_for: None,
    })
}

// Buffered fold over a complete NDJSON body. Production path on wasm32
// (no chunk reader on the browser-fetch backend); native production goes
// through `drain_account_subscribe_response`, so this is test-only there.
#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
pub(crate) fn parse_account_subscribe_snapshot_outcome(
    bytes: &[u8],
) -> anyhow::Result<AccountSubscribeSnapshotResult> {
    let trimmed_body = trim_ascii(bytes);
    let is_single_frame = serde_json::from_slice::<Value>(trimmed_body)
        .ok()
        .and_then(|value| value.get("kind").cloned())
        .is_some();
    if !is_single_frame
        && let Ok(response) = serde_json::from_slice::<ClientSyncOutcome>(trimmed_body)
    {
        return Ok(AccountSubscribeSnapshotResult::Delta(Box::new(response)));
    }

    let mut folder = new_account_subscribe_folder();
    for line in bytes.split(|byte| *byte == b'\n') {
        let trimmed = trim_ascii(line);
        if trimmed.is_empty() {
            continue;
        }
        let frame: arkret_sdk::AccountSubscribeFrame = serde_json::from_slice(trimmed)?;
        if folder.push(frame)? {
            break;
        }
    }
    Ok(folder.finish()?)
}

/// Native streaming reader: consume the account-subscribe NDJSON response
/// frame by frame and stop as soon as the snapshot scope is decided
/// (`catchup_complete` / control frame) instead of buffering the whole
/// body — against a spec-compliant server that keeps the stream open for
/// realtime push, `Response::bytes()` would block until timeout.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn drain_account_subscribe_response(
    mut response: reqwest::Response,
) -> anyhow::Result<AccountSubscribeSnapshotResult> {
    let mut folder = new_account_subscribe_folder();
    let mut pending: Vec<u8> = Vec::new();
    'stream: while let Some(chunk) = response.chunk().await? {
        pending.extend_from_slice(&chunk);
        // Cap the inter-newline buffer: a server that never delimits a frame
        // (or sends an oversized single frame) MUST NOT be able to grow this
        // buffer without bound. Fail closed instead of risking OOM.
        if pending.len() > MAX_NDJSON_STREAM_FRAME_BYTES {
            anyhow::bail!(
                "account subscribe frame exceeded {MAX_NDJSON_STREAM_FRAME_BYTES} bytes without a newline delimiter"
            );
        }
        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = pending.drain(..=newline).collect();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let trimmed = trim_ascii(&line);
            if trimmed.is_empty() {
                continue;
            }
            let frame: arkret_sdk::AccountSubscribeFrame = serde_json::from_slice(trimmed)?;
            if folder.push(frame)? {
                break 'stream;
            }
        }
    }
    // Flush a final unterminated line (server closed without trailing \n).
    let trimmed = trim_ascii(&pending);
    if !trimmed.is_empty() {
        let frame: arkret_sdk::AccountSubscribeFrame = serde_json::from_slice(trimmed)?;
        folder.push(frame)?;
    }
    Ok(folder.finish()?)
}
