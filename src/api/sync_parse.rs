use super::*;

pub fn parse_sync(value: Value) -> anyhow::Result<ClientSyncOutcome> {
    Ok(serde_json::from_value(value)?)
}

/// Maximum bytes the native NDJSON streaming reader will buffer before a
/// newline is seen. A spec-compliant server delimits every frame with `\n`;
/// a faulty/malicious server that keeps pushing bytes without a delimiter
/// (or a single oversized frame) would otherwise grow `pending` without
/// bound until the client OOMs. Frames are small control/delta envelopes;
/// 16 MiB is far above any legitimate single frame yet caps the OOM vector.
#[cfg(not(target_arch = "wasm32"))]
const MAX_ACCOUNT_SUBSCRIBE_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// COR-09: upper bound on a server-supplied control-frame `reconnect_after_ms`.
/// Mirrors the HTTP `Retry-After` ceiling (`MAX_RETRY_DELAY` = 60s) so the
/// clamp lives at the SDK→outcome boundary and does NOT depend on every
/// downstream consumer remembering to `.min(..)` the raw value. A malicious
/// server can therefore never "park" a reconnect for an arbitrarily long delay.
const MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 60_000;

/// Clamp a control-frame reconnect delay (or substitute the default when the
/// frame omitted one) to [`MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS`].
fn clamp_reconnect_after_ms(raw: Option<u64>) -> u64 {
    raw.unwrap_or(DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS)
        .min(MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS)
}

#[cfg(test)]
pub(crate) fn parse_account_subscribe_snapshot(bytes: &[u8]) -> anyhow::Result<ClientSyncOutcome> {
    match parse_account_subscribe_snapshot_outcome(bytes)? {
        AccountSubscribeSnapshotResult::Delta(response) => Ok(*response),
        AccountSubscribeSnapshotResult::ReconnectAfter {
            reconnect_after_ms,
            reason,
            reset_cursor,
        } => Err(AccountSubscribeReconnectAfter {
            reconnect_after_ms,
            reason,
            reset_cursor,
        }
        .into()),
    }
}

/// Incremental folder for `ck.self.account.stream.subscribe` NDJSON frames.
///
/// YOU-01-010: consumes EVERY frame instead of returning at the first
/// `delta` — catchup deltas are merged in order, and per client-sync.md
/// §2.2 **any** frame carrying a `cursor` advances the persisted
/// high-water mark (delta / catchup_complete / frontier / heartbeat).
/// Control-frame routing:
/// - `resync_required` / `unauthorized` → discard the accumulated state and surface
///   `ReconnectAfter` (resync resets the cursor);
/// - `dropped` → return what was accumulated (its `cursor` is the resume point) or `ReconnectAfter`
///   when nothing was accumulated yet;
/// - `catchup_complete` → the snapshot is complete; streaming readers stop consuming here instead
///   of waiting for the server to close the long-lived stream.
#[derive(Default)]
struct AccountSubscribeFolder {
    merged: Option<ClientSyncOutcome>,
    latest_cursor: Option<String>,
    done: Option<AccountSubscribeSnapshotResult>,
}

impl AccountSubscribeFolder {
    /// Feed one frame. Returns `true` when the outcome is decided and the
    /// caller can stop reading the stream.
    fn push(&mut self, frame: cokret_sdk::AccountSubscribeFrame) -> bool {
        if self.done.is_some() {
            return true;
        }
        if let Some(cursor) = frame.cursor.as_deref().filter(|c| !c.trim().is_empty()) {
            self.latest_cursor = Some(cursor.to_owned());
        }
        match frame.kind {
            cokret_sdk::AccountSubscribeFrameKind::ResyncRequired
            | cokret_sdk::AccountSubscribeFrameKind::Unauthorized => {
                self.done = Some(AccountSubscribeSnapshotResult::ReconnectAfter {
                    reconnect_after_ms: clamp_reconnect_after_ms(frame.reconnect_after_ms()),
                    reason: frame.reason,
                    reset_cursor: frame.kind
                        == cokret_sdk::AccountSubscribeFrameKind::ResyncRequired,
                });
                return true;
            }
            cokret_sdk::AccountSubscribeFrameKind::Dropped => {
                if self.merged.is_none() {
                    self.done = Some(AccountSubscribeSnapshotResult::ReconnectAfter {
                        reconnect_after_ms: clamp_reconnect_after_ms(frame.reconnect_after_ms()),
                        reason: frame.reason,
                        reset_cursor: false,
                    });
                }
                // A dropped frame closes this snapshot scope. If we already
                // folded a delta, finish() returns that delta with the dropped
                // cursor as resume point; otherwise it surfaces ReconnectAfter.
                return true;
            }
            cokret_sdk::AccountSubscribeFrameKind::CatchupComplete => {
                // catchup_complete marks the baseline as complete; whatever
                // was folded is valid up to `latest_cursor`.
                return true;
            }
            _ => {}
        }
        if let Some(delta) = ClientSyncOutcome::from_account_subscribe_frame(frame) {
            self.merged = Some(match self.merged.take() {
                None => delta,
                Some(mut acc) => {
                    merge_account_subscribe_delta(&mut acc, delta);
                    acc
                }
            });
        }
        false
    }

    fn finish(self) -> anyhow::Result<AccountSubscribeSnapshotResult> {
        if let Some(done) = self.done {
            return Ok(done);
        }
        match self.merged {
            Some(mut response) => {
                if let Some(cursor) = self.latest_cursor {
                    response.cursor = cursor;
                }
                Ok(AccountSubscribeSnapshotResult::Delta(Box::new(response)))
            }
            None => anyhow::bail!("account subscribe stream ended before a delta frame"),
        }
    }
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

    let mut folder = AccountSubscribeFolder::default();
    for line in bytes.split(|byte| *byte == b'\n') {
        let trimmed = trim_ascii(line);
        if trimmed.is_empty() {
            continue;
        }
        let frame: cokret_sdk::AccountSubscribeFrame = serde_json::from_slice(trimmed)?;
        if folder.push(frame) {
            break;
        }
    }
    folder.finish()
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
    let mut folder = AccountSubscribeFolder::default();
    let mut pending: Vec<u8> = Vec::new();
    'stream: while let Some(chunk) = response.chunk().await? {
        pending.extend_from_slice(&chunk);
        // Cap the inter-newline buffer: a server that never delimits a frame
        // (or sends an oversized single frame) MUST NOT be able to grow this
        // buffer without bound. Fail closed instead of risking OOM.
        if pending.len() > MAX_ACCOUNT_SUBSCRIBE_FRAME_BYTES {
            anyhow::bail!(
                "account subscribe frame exceeded {MAX_ACCOUNT_SUBSCRIBE_FRAME_BYTES} bytes without a newline delimiter"
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
            let frame: cokret_sdk::AccountSubscribeFrame = serde_json::from_slice(trimmed)?;
            if folder.push(frame) {
                break 'stream;
            }
        }
    }
    // Flush a final unterminated line (server closed without trailing \n).
    let trimmed = trim_ascii(&pending);
    if !trimmed.is_empty() {
        let frame: cokret_sdk::AccountSubscribeFrame = serde_json::from_slice(trimmed)?;
        folder.push(frame);
    }
    folder.finish()
}

/// Merge a later catchup `delta` into the accumulated snapshot. Realm
/// entries deep-merge their event arrays so multi-frame catchup does not
/// drop earlier batches; list-shaped account channels append; scalar
/// channels take the newest value.
fn merge_account_subscribe_delta(acc: &mut ClientSyncOutcome, next: ClientSyncOutcome) {
    for (realm_id, incoming) in next.realms {
        match acc.realms.entry(realm_id) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(incoming);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                merge_realm_delta_value(slot.get_mut(), incoming);
            }
        }
    }
    acc.cursor = next.cursor;
    acc.left_realms.extend(next.left_realms);
    acc.to_device.extend(next.to_device);
    if next.to_device_ack_token.is_some() {
        acc.to_device_ack_token = next.to_device_ack_token;
    }
    acc.to_device_limited = next.to_device_limited;
    if next.to_device_next_cursor.is_some() {
        acc.to_device_next_cursor = next.to_device_next_cursor;
    }
    if next.to_device_lost.is_some() {
        acc.to_device_lost = next.to_device_lost;
    }
    acc.account_data.extend(next.account_data);
    acc.presence.extend(next.presence);
    if !next.device_lists.is_null() {
        acc.device_lists = next.device_lists;
    }
    if !next.notifications.is_null() {
        acc.notifications = next.notifications;
    }
    acc.partial = next.partial;
}

/// Best-effort deep merge of one realm's delta body: `timeline.events` and
/// `state.events` arrays append, every other key takes the incoming value.
fn merge_realm_delta_value(current: &mut Value, incoming: Value) {
    let Value::Object(incoming) = incoming else {
        *current = incoming;
        return;
    };
    let Value::Object(current_map) = current else {
        *current = Value::Object(incoming);
        return;
    };
    for (key, value) in incoming {
        if (key == "timeline" || key == "state")
            && let Some(Value::Object(existing_section)) = current_map.get_mut(&key)
            && let Value::Object(mut incoming_section) = value
        {
            if let (Some(Value::Array(existing_events)), Some(Value::Array(new_events))) = (
                existing_section.get_mut("events"),
                incoming_section.remove("events"),
            ) {
                existing_events.extend(new_events);
            }
            for (section_key, section_value) in incoming_section {
                existing_section.insert(section_key, section_value);
            }
            continue;
        }
        current_map.insert(key, value);
    }
}

#[cfg(test)]
mod cor09_tests {
    use super::{
        DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS, MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS,
        clamp_reconnect_after_ms,
    };

    #[test]
    fn clamp_caps_oversized_server_value() {
        // COR-09: a hostile server value is clamped to the ceiling.
        assert_eq!(
            clamp_reconnect_after_ms(Some(u64::MAX)),
            MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS
        );
    }

    #[test]
    fn clamp_passes_through_reasonable_value() {
        assert_eq!(clamp_reconnect_after_ms(Some(2_000)), 2_000);
    }

    #[test]
    fn clamp_substitutes_default_when_absent() {
        assert_eq!(
            clamp_reconnect_after_ms(None),
            DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS
        );
    }
}
