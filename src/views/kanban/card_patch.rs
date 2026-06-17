use serde_json::{Map, Value, json};

use super::model::*;
use super::{
    display_optional_card_field, editor_value_for_optional_card_field,
    value_is_plaintext_private_content,
};

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

    let description = draft.description.trim();
    if current.description.trim() != description {
        let op = if description.is_empty() {
            json!({ "$op": "unset" })
        } else {
            json!({ "$op": "set", "value": description })
        };
        patch.insert("metadata.summary".to_owned(), op);
    }

    let body = draft.body.trim();
    if current.body.trim() != body {
        let op = if body.is_empty() {
            json!({ "$op": "unset" })
        } else {
            json!({ "$op": "set", "value": body })
        };
        patch.insert("body".to_owned(), op);
    }

    let synthesis = draft.synthesis.trim();
    if current.synthesis.trim() != synthesis {
        let op = if synthesis.is_empty() {
            json!({ "$op": "unset" })
        } else {
            json!({ "$op": "set", "value": synthesis })
        };
        patch.insert("synthesis".to_owned(), op);
    }

    let current_due = editor_value_for_optional_card_field(&current.due);
    let fields_changed = current.labels != draft.labels || current_due != draft.due.trim();
    if fields_changed {
        let mut fields = Map::new();
        fields.insert("labels".to_owned(), json!(draft.labels.clone()));
        let due = draft.due.trim();
        if !due.is_empty() && due != "—" {
            fields.insert("due_at".to_owned(), json!(due));
        }
        patch.insert(
            "metadata.fields".to_owned(),
            json!({ "$op": "set", "value": Value::Object(fields) }),
        );
    }

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
    let next_due = draft.due.trim();
    if current_due != next_due {
        return if next_due.is_empty() || next_due == "—" {
            "Due date cleared".to_owned()
        } else {
            format!("Due date set to {next_due}")
        };
    }
    if current.labels != draft.labels {
        return "Labels updated".to_owned();
    }
    if current.title.trim() != draft.title.trim()
        || current.description.trim() != draft.description.trim()
        || current.body.trim() != draft.body.trim()
        || current.synthesis.trim() != draft.synthesis.trim()
    {
        return "Card details updated".to_owned();
    }
    "Card updated".to_owned()
}

pub(super) fn apply_card_detail_draft(card: &mut KanbanCard, draft: &CardDetailDraft) {
    card.title = draft.title.trim().to_owned();
    card.description = draft.description.trim().to_owned();
    card.body = draft.body.trim().to_owned();
    card.synthesis = draft.synthesis.trim().to_owned();
    card.labels = draft.labels.clone();
    card.due = display_optional_card_field(&draft.due);
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
        let Some(patch_value) = object.get_mut(path) else {
            return Err(format!("internal: missing private patch path {path}"));
        };
        if let Some(value) = patch_value.get_mut("value") {
            *value = encrypted_value;
        } else {
            *patch_value = encrypted_value;
        }
    }
    Ok(())
}
