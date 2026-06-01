//! F-PRESENCE-RX-1: receive-side helpers for `cx.typing`, `cx.presence`,
//! and `cx.read_cursor.advance` events.
//!
//! Yougen currently emits these three event kinds (see
//! `api.rs::send_typing` etc.) but never parses them on the receive
//! side — the sync engine routes events through projection-shape
//! sections rather than per-kind dispatch, and ephemeral signaling
//! lands nowhere. This module ships the typed parsers + an in-memory
//! aggregate the chat / dashboard views can render off of.
//!
//! Spec sources:
//! - `discovery/read-receipts.md §6` — `cx.read_cursor.advance` carries a
//!   `cx.schema.read_cursor.v1` payload with `{realm_id, read_scope, position}`.
//! - `discovery/profiles-presence.md` — `cx.presence` carries `{actor_id, status, last_seen?}`
//!   with status ∈ {`online`, `away`, `dnd`, `offline`}.
//! - `flow-and-message.md §10` — `cx.typing` is short-TTL signaling carrying `{actor_id, flow_id,
//!   started_at}`.
//!
//! The parsers are deliberately permissive at the field level — they
//! collapse missing optional fields rather than rejecting the whole
//! event, so a server that adds a new optional field doesn't break
//! the receiver. They DO reject anything missing the canonical
//! required field set so a malformed event can't leak in.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Presence status as published in `cx.presence` payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    Online,
    Away,
    Dnd,
    Offline,
}

impl PresenceStatus {
    /// Parse the wire string. Unknown values fall back to `Offline`
    /// per spec — the receiver MUST NOT crash on a new server
    /// adding a status variant.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "online" => Self::Online,
            "away" => Self::Away,
            "dnd" => Self::Dnd,
            _ => Self::Offline,
        }
    }

    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Away => "away",
            Self::Dnd => "dnd",
            Self::Offline => "offline",
        }
    }
}

/// `cx.typing` event parsed from the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypingEvent {
    pub actor_id: String,
    pub flow_id: String,
    /// Optional Unix-seconds timestamp the typing notification was
    /// issued at. None when the server didn't include one — the
    /// receiver should treat that as "now" for staleness checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<i64>,
}

/// `cx.presence` event parsed from the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceEvent {
    pub actor_id: String,
    pub status: PresenceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
}

/// `cx.read_cursor.advance` event parsed from the wire. HLC is kept as a
/// string so this receive helper does not need to share the writer's clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadMarkerEvent {
    pub realm_id: String,
    pub actor_id: String,
    pub device_id: String,
    pub read_scope: ReadScopeEvent,
    pub position: ReadCursorPositionEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadScopeEvent {
    pub kind: String,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(
        rename = "track_name",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub track: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_scope: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadCursorPositionEvent {
    pub event_id: String,
    pub hlc: String,
}

/// Errors surfaced by the typed parsers when the payload is missing
/// a required field. Yougen surfaces these into the audit log so a
/// receiver-side schema drift is visible rather than swallowed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresenceRxError {
    MissingField {
        event_kind: &'static str,
        field: &'static str,
    },
    WrongKind {
        expected: &'static str,
        actual: String,
    },
}

impl std::fmt::Display for PresenceRxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField { event_kind, field } => {
                write!(f, "{event_kind} payload missing required field `{field}`")
            }
            Self::WrongKind { expected, actual } => {
                write!(f, "expected event kind `{expected}` but got `{actual}`")
            }
        }
    }
}

impl std::error::Error for PresenceRxError {}

/// Parse a `cx.typing` envelope's payload into a [`TypingEvent`].
pub fn parse_typing(
    envelope: &crate::operation::EventEnvelope,
) -> Result<TypingEvent, PresenceRxError> {
    require_kind(&envelope.kind, "cx.typing")?;
    let payload = &envelope.payload;
    Ok(TypingEvent {
        actor_id: required_str(payload, "cx.typing", "actor_id")?.to_owned(),
        flow_id: required_str(payload, "cx.typing", "flow_id")?.to_owned(),
        started_at: payload.get("started_at").and_then(|v| v.as_i64()),
    })
}

/// Parse a `cx.presence` envelope's payload into a [`PresenceEvent`].
pub fn parse_presence(
    envelope: &crate::operation::EventEnvelope,
) -> Result<PresenceEvent, PresenceRxError> {
    require_kind(&envelope.kind, "cx.presence")?;
    let payload = &envelope.payload;
    let status_str = required_str(payload, "cx.presence", "status")?;
    Ok(PresenceEvent {
        actor_id: required_str(payload, "cx.presence", "actor_id")?.to_owned(),
        status: PresenceStatus::from_wire(status_str),
        last_seen: payload.get("last_seen").and_then(|v| v.as_i64()),
    })
}

/// Parse a `cx.read_cursor.advance` envelope's payload into a [`ReadMarkerEvent`].
pub fn parse_read_cursor(
    envelope: &crate::operation::EventEnvelope,
) -> Result<ReadMarkerEvent, PresenceRxError> {
    require_kind(&envelope.kind, "cx.read_cursor.advance")?;
    let payload = &envelope.payload;
    let read_scope = required_value(payload, "cx.read_cursor.advance", "read_scope")?;
    let read_scope =
        serde_json::from_value::<ReadScopeEvent>(read_scope.clone()).map_err(|_| {
            PresenceRxError::MissingField {
                event_kind: "cx.read_cursor.advance",
                field: "read_scope.kind",
            }
        })?;
    if !matches!(
        read_scope.kind.as_str(),
        "realm" | "flow" | "thread" | "view" | "message" | "morph"
    ) {
        return Err(PresenceRxError::MissingField {
            event_kind: "cx.read_cursor.advance",
            field: "read_scope.kind",
        });
    }
    let position = required_value(payload, "cx.read_cursor.advance", "position")?;
    let position =
        serde_json::from_value::<ReadCursorPositionEvent>(position.clone()).map_err(|_| {
            PresenceRxError::MissingField {
                event_kind: "cx.read_cursor.advance",
                field: "position.event_id",
            }
        })?;
    Ok(ReadMarkerEvent {
        realm_id: required_str(payload, "cx.read_cursor.advance", "realm_id")?.to_owned(),
        actor_id: required_str(payload, "cx.read_cursor.advance", "actor_id")?.to_owned(),
        device_id: required_str(payload, "cx.read_cursor.advance", "device_id")?.to_owned(),
        read_scope,
        position,
    })
}

fn require_kind(actual: &str, expected: &'static str) -> Result<(), PresenceRxError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PresenceRxError::WrongKind {
            expected,
            actual: actual.to_owned(),
        })
    }
}

fn required_str<'a>(
    payload: &'a Value,
    event_kind: &'static str,
    field: &'static str,
) -> Result<&'a str, PresenceRxError> {
    payload
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(PresenceRxError::MissingField { event_kind, field })
}

fn required_value<'a>(
    payload: &'a Value,
    event_kind: &'static str,
    field: &'static str,
) -> Result<&'a Value, PresenceRxError> {
    payload
        .get(field)
        .ok_or(PresenceRxError::MissingField { event_kind, field })
}

/// F-PRESENCE-RX-1: in-memory aggregate the chat / dashboard views
/// can read off of without re-parsing the event stream.
///
/// Typing entries age out after [`TYPING_TTL_SECONDS`] — the spec
/// doesn't pin a TTL, but soland fans them out as ephemeral signaling
/// with an implicit ~5s lifetime. We mirror that so a stale typing
/// dot doesn't linger forever after the sender's tab closes.
#[derive(Clone, Debug, Default)]
pub struct PresenceAggregate {
    presence: HashMap<String, PresenceEvent>,
    /// `(actor_id, flow_id) -> received_unix_seconds`.
    typing: HashMap<(String, String), i64>,
    /// `(realm_id, actor_id, read_scope) -> ReadMarkerEvent`.
    read_cursors: HashMap<(String, String, String), ReadMarkerEvent>,
}

/// TTL after which a typing indicator is treated as stale.
pub const TYPING_TTL_SECONDS: i64 = 5;

impl PresenceAggregate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest_typing(&mut self, event: TypingEvent, now_unix: i64) {
        let key = (event.actor_id, event.flow_id);
        self.typing.insert(key, now_unix);
    }

    pub fn ingest_presence(&mut self, event: PresenceEvent) {
        self.presence.insert(event.actor_id.clone(), event);
    }

    pub fn ingest_read_cursor(&mut self, event: ReadMarkerEvent) {
        let key = (
            event.realm_id.clone(),
            event.actor_id.clone(),
            read_scope_key(&event.read_scope),
        );
        self.read_cursors.insert(key, event);
    }

    /// Active typing indicators in `flow_id`, filtered by TTL.
    /// `now_unix` is supplied by the caller (typically `Utc::now()`)
    /// so unit tests can fix the clock.
    pub fn typing_in_flow(&self, flow_id: &str, now_unix: i64) -> Vec<String> {
        self.typing
            .iter()
            .filter_map(|((actor, flow), received_at)| {
                if flow == flow_id && now_unix - received_at <= TYPING_TTL_SECONDS {
                    Some(actor.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn presence_for(&self, actor_id: &str) -> Option<&PresenceEvent> {
        self.presence.get(actor_id)
    }

    pub fn read_cursor(
        &self,
        realm_id: &str,
        actor_id: &str,
        read_scope: &ReadScopeEvent,
    ) -> Option<&ReadMarkerEvent> {
        self.read_cursors.get(&(
            realm_id.to_owned(),
            actor_id.to_owned(),
            read_scope_key(read_scope),
        ))
    }

    /// Drop typing indicators older than [`TYPING_TTL_SECONDS`].
    /// Called by the chat view's render tick so the aggregate
    /// doesn't grow unboundedly when a sender's tab leaves without
    /// emitting a stop event.
    pub fn evict_stale_typing(&mut self, now_unix: i64) {
        self.typing
            .retain(|_, received_at| now_unix - *received_at <= TYPING_TTL_SECONDS);
    }
}

/// Helper: current Unix seconds for callers that don't have their
/// own clock. Uses `SystemTime` so it works on both native and wasm
/// targets (we already depend on `Duration` via chrono).
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

fn read_scope_key(read_scope: &ReadScopeEvent) -> String {
    format!(
        "{}\n{}\n{}",
        read_scope.kind.as_str(),
        read_scope.object_ref.as_deref().unwrap_or(""),
        read_scope
            .track
            .as_deref()
            .or(read_scope.track_scope.as_deref())
            .unwrap_or("")
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::operation::EventEnvelope;

    fn envelope(kind: &str, payload: Value) -> EventEnvelope {
        EventEnvelope {
            event_id: "cx:event:1".to_owned(),
            kind: kind.to_owned(),
            actor_id: "did:web:alice".to_owned(),
            actor_seq: 1,
            realm_id: "cx:realm:1".to_owned(),
            created_at: "2026-05-19T00:00:00Z".to_owned(),
            hlc: "01970e589d21-0001-a13f9c2e".to_owned(),
            prev_refs: Vec::new(),
            refs: Vec::new(),
            payload,
            preconditions: Vec::new(),
            effects: Vec::new(),
            anchor_ref: None,
            requirements: None,
            redacts: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        }
    }

    #[test]
    fn parse_typing_extracts_actor_and_flow() {
        let env = envelope(
            "cx.typing",
            json!({"actor_id": "did:web:alice", "flow_id": "cx:flow:1", "started_at": 1716000000}),
        );
        let parsed = parse_typing(&env).expect("parse");
        assert_eq!(parsed.actor_id, "did:web:alice");
        assert_eq!(parsed.flow_id, "cx:flow:1");
        assert_eq!(parsed.started_at, Some(1716000000));
    }

    #[test]
    fn parse_typing_started_at_is_optional() {
        let env = envelope(
            "cx.typing",
            json!({"actor_id": "did:web:alice", "flow_id": "cx:flow:1"}),
        );
        let parsed = parse_typing(&env).expect("parse");
        assert_eq!(parsed.started_at, None);
    }

    #[test]
    fn parse_typing_rejects_wrong_kind() {
        let env = envelope("cx.message.create", json!({}));
        match parse_typing(&env) {
            Err(PresenceRxError::WrongKind { expected, actual }) => {
                assert_eq!(expected, "cx.typing");
                assert_eq!(actual, "cx.message.create");
            }
            other => panic!("expected WrongKind, got {other:?}"),
        }
    }

    #[test]
    fn parse_typing_rejects_missing_required_field() {
        let env = envelope("cx.typing", json!({"actor_id": "did:web:alice"}));
        match parse_typing(&env) {
            Err(PresenceRxError::MissingField { field, .. }) => {
                assert_eq!(field, "flow_id");
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[test]
    fn parse_presence_falls_back_to_offline_for_unknown_status() {
        let env = envelope(
            "cx.presence",
            json!({"actor_id": "did:web:alice", "status": "bogus"}),
        );
        let parsed = parse_presence(&env).expect("parse");
        assert_eq!(parsed.status, PresenceStatus::Offline);
    }

    #[test]
    fn parse_read_cursor_round_trip_carries_hlc_verbatim() {
        let env = envelope(
            "cx.read_cursor.advance",
            json!({
                "schema": "cx.schema.read_cursor.v1",
                "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
                "actor_id": "did:web:alice",
                "device_id": "cx:device:01904100-0000-7000-8000-000000000001",
                "read_scope": {
                    "kind": "flow",
                    "ref": "cx:flow:01904100-0000-7000-8000-000000000001",
                    "track_name": "discussion"
                },
                "position": {
                    "event_id": "cx:event:01904100-0000-7000-8000-000000000042",
                    "hlc": "01970e589d21-0001-a13f9c2e"
                }
            }),
        );
        let parsed = parse_read_cursor(&env).expect("parse");
        assert_eq!(
            parsed.realm_id,
            "cx:realm:01904100-0000-7000-8000-000000000001"
        );
        assert_eq!(parsed.actor_id, "did:web:alice");
        assert_eq!(parsed.read_scope.kind, "flow");
        assert_eq!(parsed.read_scope.track.as_deref(), Some("discussion"));
        assert_eq!(
            parsed.position.event_id,
            "cx:event:01904100-0000-7000-8000-000000000042"
        );
        assert_eq!(parsed.position.hlc, "01970e589d21-0001-a13f9c2e");
    }

    #[test]
    fn parse_read_cursor_rejects_removed_flow_discussion_kind() {
        let env = envelope(
            "cx.read_cursor.advance",
            json!({
                "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
                "actor_id": "did:web:alice",
                "read_scope": {
                    "kind": "flow_discussion",
                    "ref": "cx:flow:01904100-0000-7000-8000-000000000001"
                },
                "position": {
                    "event_id": "cx:event:01904100-0000-7000-8000-000000000042",
                    "hlc": "01970e589d21-0001-a13f9c2e"
                }
            }),
        );
        assert!(parse_read_cursor(&env).is_err());
    }

    #[test]
    fn aggregate_evicts_stale_typing_after_ttl() {
        let mut agg = PresenceAggregate::new();
        agg.ingest_typing(
            TypingEvent {
                actor_id: "did:web:alice".to_owned(),
                flow_id: "cx:flow:1".to_owned(),
                started_at: Some(1000),
            },
            1000,
        );
        // 4 seconds later — still within TTL.
        let still_typing = agg.typing_in_flow("cx:flow:1", 1004);
        assert_eq!(still_typing, vec!["did:web:alice".to_owned()]);
        // 6 seconds later — past TTL.
        let stale = agg.typing_in_flow("cx:flow:1", 1006);
        assert!(stale.is_empty());
        agg.evict_stale_typing(1006);
        // Map should be empty now.
        assert!(agg.typing_in_flow("cx:flow:1", 1006).is_empty());
    }

    #[test]
    fn aggregate_presence_and_read_cursor_round_trip() {
        let mut agg = PresenceAggregate::new();
        agg.ingest_presence(PresenceEvent {
            actor_id: "did:web:alice".to_owned(),
            status: PresenceStatus::Away,
            last_seen: Some(1000),
        });
        agg.ingest_read_cursor(ReadMarkerEvent {
            realm_id: "cx:realm:01904100-0000-7000-8000-000000000001".to_owned(),
            actor_id: "did:web:alice".to_owned(),
            device_id: "cx:device:01904100-0000-7000-8000-000000000001".to_owned(),
            read_scope: ReadScopeEvent {
                kind: "flow".to_owned(),
                object_ref: Some("cx:flow:01904100-0000-7000-8000-000000000001".to_owned()),
                track: Some("discussion".to_owned()),
                track_scope: None,
            },
            position: ReadCursorPositionEvent {
                event_id: "cx:event:01904100-0000-7000-8000-000000000042".to_owned(),
                hlc: "01970e589d21-0001-a13f9c2e".to_owned(),
            },
        });
        let presence = agg.presence_for("did:web:alice").unwrap();
        assert_eq!(presence.status, PresenceStatus::Away);
        let scope = ReadScopeEvent {
            kind: "flow".to_owned(),
            object_ref: Some("cx:flow:01904100-0000-7000-8000-000000000001".to_owned()),
            track: Some("discussion".to_owned()),
            track_scope: None,
        };
        let marker = agg
            .read_cursor(
                "cx:realm:01904100-0000-7000-8000-000000000001",
                "did:web:alice",
                &scope,
            )
            .unwrap();
        assert_eq!(
            marker.position.event_id,
            "cx:event:01904100-0000-7000-8000-000000000042"
        );
    }

    #[test]
    fn presence_status_round_trips_through_wire_strings() {
        for variant in [
            PresenceStatus::Online,
            PresenceStatus::Away,
            PresenceStatus::Dnd,
            PresenceStatus::Offline,
        ] {
            assert_eq!(PresenceStatus::from_wire(variant.as_wire()), variant);
        }
    }
}
