use super::*;

pub(crate) fn strand_projection_field_string(
    strand: &crate::api::StrandProjectionView,
    top_level: Option<&str>,
    field_names: &[&str],
) -> Option<String> {
    top_level
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            field_names.iter().find_map(|field_name| {
                strand
                    .fields
                    .get(*field_name)
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned)
            })
        })
}

pub(crate) fn strand_projection_labels(strand: &crate::api::StrandProjectionView) -> Vec<String> {
    match strand.fields.get("labels") {
        Some(Value::Array(labels)) => labels
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Some(Value::String(labels)) => parse_card_labels(labels),
        _ => Vec::new(),
    }
}

pub(crate) fn strand_projection_assignee(
    strand: &crate::api::StrandProjectionView,
) -> Option<String> {
    if strand.assigned_actor_ids.is_empty() {
        return None;
    }
    Some(strand.assigned_actor_ids.join(", "))
}

pub(crate) fn strand_projection_assigned_to_relations(
    strand: &crate::api::StrandProjectionView,
) -> Vec<CardAssignedToRelation> {
    strand
        .assigned_to_relations
        .iter()
        .filter_map(|relation| {
            let relation_id = relation.relation_id.trim();
            let actor_id = relation.actor_id.trim();
            (!relation_id.is_empty() && !actor_id.is_empty()).then(|| CardAssignedToRelation {
                relation_id: relation_id.to_owned(),
                actor_id: actor_id.to_owned(),
            })
        })
        .collect()
}

pub(crate) fn strand_projection_security_state(
    strand: &crate::api::StrandProjectionView,
) -> Option<bool> {
    let mut value = Map::new();
    value.insert("fields".to_owned(), Value::Object(strand.fields.clone()));
    if let Some(body) = strand.body.as_ref() {
        value.insert("body".to_owned(), body.clone());
    }
    crate::security_state::strand_projection_security_state(&Value::Object(value))
}

pub(crate) fn strand_body_display_text(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    let mut lines = Vec::new();
    collect_content_text(value, &mut lines);
    lines
        .into_iter()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn collect_content_text(value: &Value, lines: &mut Vec<String>) {
    match value {
        Value::String(text) => lines.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_content_text(item, lines);
            }
        }
        Value::Object(object) => {
            for key in [
                "body",
                "text",
                "markdown",
                "plain_text",
                "content",
                "caption",
                "alt",
            ] {
                if let Some(child) = object.get(key) {
                    collect_content_text(child, lines);
                }
            }
            if let Some(blocks) = object.get("blocks") {
                collect_content_text(blocks, lines);
            }
        }
        _ => {}
    }
}

pub(crate) fn card_from_strand_projection(
    strand: &crate::api::StrandProjectionView,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> KanbanCard {
    let title = if strand.title.trim().is_empty() {
        strand.strand_id.clone()
    } else {
        strand.title.clone()
    };
    let description = strand_projection_field_string(
        strand,
        strand.summary.as_deref(),
        &["summary", "description"],
    )
    .unwrap_or_default();
    let discussion_visibility =
        strand_projection_field_string(strand, None, &["discussion_visibility", "visibility"]);
    let locked_strand = if discussion_visibility.as_deref() == Some("locked") {
        Some(LockedStrand {
            strand_id_hash: strand_projection_field_string(strand, None, &["discussion_ref_hash"])
                .unwrap_or_else(|| format!("sha256:{}", strand.strand_id)),
            reason: strand_projection_field_string(strand, None, &["locked_reason"])
                .unwrap_or_else(|| {
                    "Locked discussion: title and members are not disclosed.".to_owned()
                }),
        })
    } else {
        None
    };
    let external_visibility = if locked_strand.is_some() {
        "Locked discussion (lazy_link)".to_owned()
    } else {
        "No external discussions linked".to_owned()
    };
    let history_visibility = strand_projection_field_string(strand, None, &["history_visibility"])
        .unwrap_or_else(|| {
            if locked_strand.is_some() {
                "lazy_link (cross-Space)".to_owned()
            } else {
                "Managed by board".to_owned()
            }
        });
    // X10.2: bind the private-field value exprs once so text + locked agree.
    let strand_body_field =
        strand_projection_private_field_value(strand, KANBAN_BODY_PRIVATE_FIELD_PATHS);
    let strand_body_value = strand_body_field.map(|(value, _)| value);
    let strand_body_path = strand_body_field.map(|(_, path)| path).unwrap_or("body");
    let strand_synthesis_field =
        strand_projection_private_field_value(strand, KANBAN_SYNTHESIS_PRIVATE_FIELD_PATHS);
    let strand_synthesis_value = strand_synthesis_field.map(|(value, _)| value);
    let strand_synthesis_path = strand_synthesis_field
        .map(|(_, path)| path)
        .unwrap_or("synthesis");
    KanbanCard {
        id: strand.strand_id.clone(),
        rank: strand_projection_field_string(strand, strand.rank.as_deref(), &["rank"])
            .unwrap_or_default(),
        title: title.clone(),
        description,
        body: private_strand_field_text(
            decrypt_ctx,
            &strand.strand_id,
            strand_body_path,
            strand_body_value,
        ),
        body_locked: private_strand_field_locked(
            decrypt_ctx,
            &strand.strand_id,
            strand_body_path,
            strand_body_value,
        ),
        synthesis: private_strand_field_text(
            decrypt_ctx,
            &strand.strand_id,
            strand_synthesis_path,
            strand_synthesis_value,
        ),
        synthesis_locked: private_strand_field_locked(
            decrypt_ctx,
            &strand.strand_id,
            strand_synthesis_path,
            strand_synthesis_value,
        ),
        created_by: strand
            .created_by
            .clone()
            .or_else(|| strand_projection_field_string(strand, None, &["created_by", "actor_id"]))
            .unwrap_or_default(),
        created_at: strand
            .created_at
            .clone()
            .or_else(|| strand_projection_field_string(strand, None, &["created_at", "timestamp"]))
            .unwrap_or_default(),
        updated_at: strand
            .updated_at
            .clone()
            .or_else(|| strand_projection_field_string(strand, None, &["updated_at", "edited_at"]))
            .unwrap_or_default(),
        labels: strand_projection_labels(strand),
        assignee: strand_projection_assignee(strand).unwrap_or_else(|| "—".to_owned()),
        assigned_to_relations: strand_projection_assigned_to_relations(strand),
        due: strand_projection_field_string(strand, None, &["due_at", "due"])
            .unwrap_or_else(|| "—".to_owned()),
        primary_strand_id: strand.strand_id.clone(),
        locked_strand,
        external_visibility,
        history_visibility,
        security_encrypted: strand_projection_security_state(strand),
        state: CardState::Synced,
        lifecycle: strand_lifecycle_from_wire(&strand.state),
    }
}
