use super::*;

pub(crate) fn strand_projection_field_string(
    strand: &crate::state::projection_views::StrandProjectionView,
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

pub(crate) fn strand_projection_labels(
    strand: &crate::state::projection_views::StrandProjectionView,
) -> Vec<String> {
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
    strand: &crate::state::projection_views::StrandProjectionView,
) -> Option<String> {
    if strand.assigned_actor_ids.is_empty() {
        return None;
    }
    Some(strand.assigned_actor_ids.join(", "))
}

pub(crate) fn strand_projection_assigned_to_relations(
    strand: &crate::state::projection_views::StrandProjectionView,
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

// The `expect` asserts the path-nesting invariant named in its message:
// `strand_projection_synthesis_content` only yields paths under
// `tracks.synthesis`.
#[allow(clippy::expect_used)]
pub(crate) fn strand_projection_security_state(
    strand: &crate::state::projection_views::StrandProjectionView,
) -> Option<bool> {
    let mut value = Map::new();
    value.insert("fields".to_owned(), Value::Object(strand.fields.clone()));
    if let Some((content, path)) = strand_projection_description_content(strand) {
        value.insert(path.to_owned(), content);
    }
    if let Some((content, path)) = strand_projection_synthesis_content(strand) {
        let leaf = path
            .strip_prefix("tracks.synthesis.")
            .expect("Synthesis projection paths are nested under tracks.synthesis");
        value.insert(
            "tracks".to_owned(),
            serde_json::json!({"synthesis": {(leaf): content}}),
        );
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
                "parts",
                "caption",
                "alt",
            ] {
                if let Some(child) = object.get(key) {
                    collect_content_text(child, lines);
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn card_from_strand_projection(
    strand: &crate::state::projection_views::StrandProjectionView,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
) -> KanbanCard {
    card_from_strand_projection_for_actor(strand, decrypt_ctx, "")
}

/// Same as [`card_from_strand_projection`], with the signed-in actor so the
/// card can mark which RSVP head is the viewer's own answer.
pub(crate) fn card_from_strand_projection_for_actor(
    strand: &crate::state::projection_views::StrandProjectionView,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
    self_actor_id: &str,
) -> KanbanCard {
    let title = if strand.title.trim().is_empty() {
        strand.strand_id.clone()
    } else {
        strand.title.clone()
    };
    let summary = strand_projection_field_string(
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
    let history_access = strand_projection_field_string(strand, None, &["history_access"])
        .unwrap_or_else(|| {
            if locked_strand.is_some() {
                "lazy_link (cross-Space)".to_owned()
            } else {
                "Managed by board".to_owned()
            }
        });
    // X10.2: bind the content value + its canonical path once so the display
    // text and the locked decision can never read different sources.
    let strand_description_field = strand_projection_description_content(strand);
    let strand_description_value = strand_description_field.as_ref().map(|(value, _)| value);
    let strand_description_path = strand_description_field
        .as_ref()
        .map(|(_, path)| *path)
        .unwrap_or(KANBAN_CONTENT_PATH);
    let strand_synthesis_field = strand_projection_synthesis_content(strand);
    let strand_synthesis_value = strand_synthesis_field.as_ref().map(|(value, _)| value);
    let strand_synthesis_path = strand_synthesis_field
        .as_ref()
        .map(|(_, path)| *path)
        .unwrap_or(KANBAN_SYNTHESIS_CONTENT_PATH);
    KanbanCard {
        id: strand.strand_id.clone(),
        rank: strand_projection_field_string(strand, strand.rank.as_deref(), &["rank"])
            .unwrap_or_default(),
        title: title.clone(),
        description: summary,
        description_body: private_strand_field_text(
            decrypt_ctx,
            &strand.strand_id,
            strand_description_path,
            strand_description_value,
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
        description_locked: private_strand_field_locked(
            decrypt_ctx,
            &strand.strand_id,
            strand_description_path,
            strand_description_value,
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
        updated_by: strand
            .updated_by
            .clone()
            .or_else(|| strand_projection_field_string(strand, None, &["updated_by"]))
            .unwrap_or_default(),
        updated_at: strand
            .updated_at
            .clone()
            .or_else(|| strand_projection_field_string(strand, None, &["updated_at", "edited_at"]))
            .unwrap_or_default(),
        labels: strand_projection_labels(strand),
        assignee: strand_projection_assignee(strand).unwrap_or_else(|| "—".to_owned()),
        assigned_to_relations: strand_projection_assigned_to_relations(strand),
        due: strand_projection_field_string(strand, None, &["due_at", "due", "due_date"])
            .unwrap_or_else(|| "—".to_owned()),
        // Fold the projected RSVP heads for the card's base occurrence. The
        // self actor is filled in by the view layer, which knows the session.
        calendar_rsvp: calendar_rsvp_display(
            &strand.rsvps,
            &strand.schedule_revision_heads,
            None,
            self_actor_id,
        ),
        calendar_schedule_basis_refs: strand.schedule_revision_heads.clone(),
        calendar: calendar_fields_from_metadata(&strand.fields, decrypt_ctx, &strand.strand_id),
        primary_strand_id: strand.strand_id.clone(),
        locked_strand,
        external_visibility,
        history_access,
        security_encrypted: strand_projection_security_state(strand),
        state: CardState::Synced,
        lifecycle: strand_lifecycle_from_projection(&strand.state),
    }
}
