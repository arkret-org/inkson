use serde_json::{Map, Value, json};

use super::model::*;
use super::{
    display_optional_card_field, editor_value_for_optional_card_field,
    value_is_plaintext_private_content,
};

/// Build a canonical ContentBlock patch op for Description or Synthesis.
///
/// The value is always a ContentBlock — `strand.schema.json` types top-level
/// `content` as `content_block`, so a bare string is a schema violation.
/// Clearing the text writes an empty-bodied block rather than `$op: unset`:
/// `content` is a registered redactable content-carrier slot
/// (`redactable-field-registry.json`), and `event-and-patch.md` §4.2.4 makes an
/// empty-bodied `set` its non-terminal clear path while reserving slot absence
/// for `ak.redaction`. Its E2EE dual `encrypted_content` is registered as the
/// paired slot, so the plaintext and encrypted branches behave identically.
fn strand_content_patch_value(text: &str) -> Result<Value, String> {
    if text.chars().count() > KANBAN_CONTENT_TEXT_MAX_CHARS {
        return Err(format!(
            "card content exceeds the {KANBAN_CONTENT_TEXT_MAX_CHARS} character inline limit for ak.content.text"
        ));
    }
    let block = arkret_sdk::ContentBlock::markdown_text(text);
    let value = serde_json::to_value(&block)
        .map_err(|err| format!("cannot serialize card content block: {err}"))?;
    Ok(json!({ "$op": "set", "value": value }))
}

pub(super) fn card_detail_update_patch(
    current: &KanbanCard,
    draft: &CardDetailDraft,
) -> Result<Value, String> {
    let title = draft.title.trim();
    if title.is_empty() {
        return Err("card title is required".to_owned());
    }
    if title.chars().count() > 512 {
        return Err("card title exceeds 512 characters".to_owned());
    }
    if draft.description.chars().count() > 2048 {
        return Err("card description exceeds 2048 characters".to_owned());
    }

    let mut patch = Map::new();
    if current.title.trim() != title {
        patch.insert(
            "metadata.title".to_owned(),
            json!({ "$op": "set", "value": title }),
        );
    }

    // `metadata.summary` has no empty representation: `strand.schema.json`
    // types it as the `short_text` string profile, whose `minLength` is 1. It is
    // not a redactable content slot either — `redactable-field-registry.json`
    // registers the Description pair (`content` / `encrypted_content`) and the
    // independent Synthesis pair under `tracks.synthesis` — so
    // `event-and-patch.md` §4.2.4 makes `$op: unset` the summary's one legal
    // non-terminal clear path.
    let description = draft.description.trim();
    if current.description.trim() != description {
        let op = if description.is_empty() {
            json!({ "$op": "unset" })
        } else {
            json!({ "$op": "set", "value": description })
        };
        patch.insert("metadata.summary".to_owned(), op);
    }

    let description_body = draft.description_body.trim();
    if current.description_body.trim() != description_body {
        patch.insert(
            KANBAN_CONTENT_PATH.to_owned(),
            strand_content_patch_value(description_body)?,
        );
    }

    let synthesis = draft.synthesis.trim();
    if current.synthesis.trim() != synthesis {
        patch.insert(
            KANBAN_SYNTHESIS_CONTENT_PATH.to_owned(),
            strand_content_patch_value(synthesis)?,
        );
    }

    if current.labels != draft.labels {
        patch.insert(
            "metadata.fields.labels".to_owned(),
            json!({ "$op": "set", "value": draft.labels.clone() }),
        );
    }

    let current_due = editor_value_for_optional_card_field(&current.due);
    let draft_due = editor_value_for_optional_card_field(&draft.due);
    if current_due != draft_due {
        let op = if draft_due.is_empty() {
            json!({ "$op": "unset" })
        } else {
            json!({ "$op": "set", "value": draft_due })
        };
        patch.insert("metadata.fields.due_at".to_owned(), op);
    }

    calendar_patch_entries(&mut patch, &current.calendar, &draft.calendar)?;

    if patch.is_empty() {
        return Err("no card detail changes to save".to_owned());
    }
    Ok(Value::Object(patch))
}

pub(super) fn card_detail_activity_summary(
    current: &KanbanCard,
    draft: &CardDetailDraft,
) -> String {
    let current_due = editor_value_for_optional_card_field(&current.due);
    let next_due = editor_value_for_optional_card_field(&draft.due);
    if current_due != next_due {
        return if next_due.is_empty() {
            "Due date cleared".to_owned()
        } else {
            format!("Due date set to {next_due}")
        };
    }
    if current.labels != draft.labels {
        return "Labels updated".to_owned();
    }
    if current.calendar != draft.calendar {
        return "Calendar schedule updated".to_owned();
    }
    if current.title.trim() != draft.title.trim()
        || current.description.trim() != draft.description.trim()
        || current.description_body.trim() != draft.description_body.trim()
        || current.synthesis.trim() != draft.synthesis.trim()
    {
        return "Card details updated".to_owned();
    }
    "Card updated".to_owned()
}

pub(super) fn apply_card_detail_draft(card: &mut KanbanCard, draft: &CardDetailDraft) {
    card.title = draft.title.trim().to_owned();
    card.description = draft.description.trim().to_owned();
    card.description_body = draft.description_body.trim().to_owned();
    card.synthesis = draft.synthesis.trim().to_owned();
    card.labels = draft.labels.clone();
    card.assignee = display_optional_card_field(&draft.assignee);
    card.due = display_optional_card_field(&draft.due);
    card.calendar = draft.calendar.clone();
    card.state = CardState::Queued;
}

pub(super) fn kanban_private_patch_path(path: &str) -> bool {
    KANBAN_PRIVATE_STRAND_PATCH_PATHS
        .iter()
        .any(|private_path| path == *private_path || path.starts_with(&format!("{private_path}.")))
}

pub(super) fn patch_plaintext_value_bytes(value: &Value) -> Result<Option<Vec<u8>>, String> {
    if let Some(object) = value.as_object()
        && object.get("$op").and_then(Value::as_str) == Some("unset")
    {
        return Ok(None);
    }
    let candidate = value.get("value").unwrap_or(value);
    if !value_is_plaintext_private_content(candidate) {
        return Ok(None);
    }
    serde_json::to_vec(candidate)
        .map(Some)
        .map_err(|err| format!("cannot serialize private patch value for encryption: {err}"))
}

pub(super) fn collect_encryptable_private_patch_values(
    patch: &Value,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let Some(object) = patch.as_object() else {
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for (path, patch_value) in object {
        if !kanban_private_patch_path(path) {
            continue;
        }
        if let Some(bytes) = patch_plaintext_value_bytes(patch_value)? {
            values.push((path.clone(), bytes));
        }
    }
    Ok(values)
}

/// Swap each collected plaintext patch value for its `EncryptedEnvelope`.
///
/// Each plaintext narrative path MOVES to its own encrypted counterpart:
/// Description `content` → `encrypted_content`, and Synthesis
/// `tracks.synthesis.content` → `tracks.synthesis.encrypted_content`.
pub(super) fn replace_private_patch_values(
    patch: &mut Value,
    paths: &[String],
    encrypted_values: Vec<Value>,
) -> Result<(), String> {
    if paths.len() != encrypted_values.len() {
        return Err("internal: encrypted patch value count mismatch".to_owned());
    }
    let Some(object) = patch.as_object_mut() else {
        return Ok(());
    };
    for (path, encrypted_value) in paths.iter().zip(encrypted_values) {
        let Some(mut patch_value) = object.remove(path) else {
            return Err(format!("internal: missing private patch path {path}"));
        };
        if let Some(value) = patch_value.get_mut("value") {
            *value = encrypted_value;
        } else {
            patch_value = encrypted_value;
        }
        object.insert(kanban_encrypted_patch_path(path).to_owned(), patch_value);
    }
    Ok(())
}
