use arkret_sdk::EventPayloadExt as _;
use serde_json::Value;

use super::model::*;

pub(super) fn value_is_plaintext_private_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(object) => {
            let encrypted_profile =
                object
                    .get("profile")
                    .and_then(Value::as_str)
                    .is_some_and(|profile| {
                        profile == "org.arkret.inkson.profile.encrypted_envelope.v1"
                    });
            !(encrypted_profile
                || object.contains_key("encrypted_content")
                || object.contains_key("ciphertext"))
        }
        Value::Bool(_) | Value::Number(_) => true,
    }
}

pub(super) fn patch_op_plaintext_value(operation: &arkret_sdk::PatchOp) -> bool {
    operation
        .value()
        .is_some_and(value_is_plaintext_private_content)
}

pub(super) fn patch_value_contains_private_path(value: &Value, path: &str) -> bool {
    let Some(candidate) = value.get("value").unwrap_or(value).pointer(&format!(
        "/{}",
        path.split('.').collect::<Vec<_>>().join("/")
    )) else {
        return false;
    };
    value_is_plaintext_private_content(candidate)
}

pub(super) fn patch_touches_private_paths(
    patch: &arkret_sdk::Patch,
    private_paths: &[&str],
) -> bool {
    patch.iter().any(|(key, operation)| {
        private_paths.iter().any(|private_path| {
            if key == private_path || key.starts_with(&format!("{private_path}.")) {
                patch_op_plaintext_value(operation)
            } else if let Some(suffix) = private_path.strip_prefix(&format!("{key}.")) {
                operation
                    .value()
                    .is_some_and(|value| patch_value_contains_private_path(value, suffix))
            } else {
                false
            }
        })
    })
}

fn content_block_has_plaintext(block: &arkret_sdk::ContentBlock) -> bool {
    !block.body.trim().is_empty() || !block.parts.is_empty() || !block.extra.is_empty()
}

fn strand_create_has_plaintext(payload: &arkret_sdk::StrandCreatePayload) -> bool {
    // Description and Synthesis are distinct plaintext surfaces on create.
    if payload
        .object
        .content
        .as_ref()
        .is_some_and(content_block_has_plaintext)
    {
        return true;
    }
    if payload
        .object
        .tracks
        .get(arkret_sdk::STRAND_TRACK_NAME_SYNTHESIS)
        .and_then(|track| track.content.as_ref())
        .is_some_and(content_block_has_plaintext)
    {
        return true;
    }
    payload
        .object
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.fields.get("calendar"))
        .and_then(|calendar| calendar.get("location"))
        .is_some_and(value_is_plaintext_private_content)
}

pub(super) fn kanban_event_carries_plaintext_private_content(event: &arkret_sdk::Event) -> bool {
    match &event.kind {
        arkret_sdk::EventKind::StrandCreate => {
            let Ok(payload) = event.typed_payload::<arkret_wire::event_spec::StrandCreate>() else {
                return true;
            };
            strand_create_has_plaintext(&payload)
        }
        arkret_sdk::EventKind::StrandUpdate => {
            let Ok(payload) = event.typed_payload::<arkret_wire::event_spec::StrandUpdate>() else {
                return true;
            };
            patch_touches_private_paths(&payload.patch, KANBAN_PRIVATE_STRAND_PATCH_PATHS)
        }
        _ => false,
    }
}

/// Event kinds that carry ONLY non-secret structural metadata (container
/// title / kind / parent / rank) and therefore MUST submit to the server as
/// plaintext even inside an encrypted Realm. Container creation (`ak.space.create`
/// for Board and List) and structural updates (`ak.space.update`) are the
/// canonical examples: a second device needs the plaintext title/rank to
/// render the Board/List name and order instead of falling back to
/// `generated_board_fallback_title` (`ak:space:...`) or stale rank order. Only
/// Strand private content (Description and the Synthesis track) is E2EE —
/// never the container scaffold. Exempting these kinds here is a hard
/// invariant: it guarantees the plaintext-block decision can never silently
/// drop a container create/update, regardless of what
/// `kanban_event_carries_plaintext_private_content` matches in the future. See
/// _next.md X13.
pub(super) const KANBAN_PLAINTEXT_METADATA_KINDS: &[arkret_sdk::EventKind] = &[
    arkret_sdk::EventKind::SpaceCreate,
    arkret_sdk::EventKind::SpaceUpdate,
];

/// R4 fail-closed reason surfaced when the Realm security projection has not
/// synced yet and we cannot prove the scope is plaintext. Mirrors the
/// `kanban.security_not_ready` i18n key.
pub(super) const SECURITY_STATE_NOT_READY_REASON: &str =
    "Security state not ready; please retry shortly before writing to this Realm.";

/// R4 (fail-closed): `scope_security_encrypted` is a THREE-STATE value:
/// - `Some(true)`  — the scope's security projection is known-encrypted.
/// - `Some(false)` — the scope's security projection is known-plaintext (a legitimate plaintext
///   Realm); plaintext writes are allowed.
/// - `None`        — the security projection is MISSING / not yet synced (first paint, incremental
///   window, projection gap). We do NOT know whether the Realm requires E2EE, so we MUST NOT
///   default to plaintext. Block the write and ask the user to retry once the projection lands;
///   otherwise a private field bound for an encrypted Realm could leak in plaintext while the
///   projection is still in flight.
pub(super) fn kanban_plaintext_block_reason(
    scope_security_encrypted: Option<bool>,
    event: &arkret_sdk::Event,
) -> Option<String> {
    match scope_security_encrypted {
        // Known plaintext Realm — legitimate plaintext write, never block.
        Some(false) => None,
        // Unknown security state — fail-closed: block plaintext private
        // content until the projection is ready. Container scaffold writes
        // (non-secret metadata) are still exempt below.
        None => {
            if !kanban_event_carries_plaintext_private_content(event) {
                return None;
            }
            if KANBAN_PLAINTEXT_METADATA_KINDS.contains(&event.kind) {
                return None;
            }
            // NB: kept as a plain string (not `i18n::tr`) so this pure guard
            // stays callable outside a Dioxus runtime (unit tests). The
            // localized copy lives under the `kanban.security_not_ready` key
            // for any UI surface that wants to translate it.
            Some(SECURITY_STATE_NOT_READY_REASON.to_owned())
        }
        // Known encrypted Realm — block plaintext private content.
        Some(true) => {
            if !kanban_event_carries_plaintext_private_content(event) {
                return None;
            }
            // Container scaffold writes (board/list title, kind, parent,
            // rank) are non-secret metadata and ALWAYS submit via the normal
            // plaintext event path even in an encrypted Realm. Never block.
            if KANBAN_PLAINTEXT_METADATA_KINDS.contains(&event.kind) {
                return None;
            }
            kanban_plaintext_block_reason_for_kind(true, event.kind.as_str())
        }
    }
}

pub(super) fn kanban_plaintext_block_reason_for_kind(
    scope_security_encrypted: bool,
    kind: &str,
) -> Option<String> {
    if !scope_security_encrypted {
        return None;
    }
    Some(format!(
        "Encrypted Realm blocks plaintext {} payload; Kanban encrypted write support is required before this event can leave the client.",
        kind
    ))
}
