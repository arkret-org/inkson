use super::*;

pub(crate) const CALENDAR_PROFILE_FIELD: &str = "profile";
pub(crate) const CALENDAR_PROFILE_REFS_FIELD: &str = "profile_refs";
pub(crate) const CALENDAR_LOCATION_PRIVATE_PATH: &str = "metadata.fields.calendar.location";
/// The single schedule namespace and its activation ref, always patched as a
/// pair.
pub(crate) const CALENDAR_SUBTREE_PATH: &str = "metadata.fields.calendar";
pub(crate) const CALENDAR_SCHEMA_REFS_PATH: &str = "schema_refs";

/// TZDB release new schedules pin when the editor has no explicit choice.
/// Must be one of `calendar-timezone-registry.json` release rows.
pub(crate) const DEFAULT_CALENDAR_TZDB_VERSION: &str = arkret_sdk::EXECUTABLE_CALENDAR_TZDB_VERSION;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CalendarCardFields {
    pub(crate) start: String,
    pub(crate) end: String,
    pub(crate) timezone: String,
    /// IANA TZDB release the schedule pins. Signed with the schedule so a
    /// receiver never resolves the zone with its own installed release.
    pub(crate) tzdb_version: String,
    pub(crate) all_day: bool,
    /// `confirmed | tentative | cancelled`. Required with no implicit default,
    /// and distinct from the Strand `stage` / `state` axes.
    pub(crate) status: String,
    pub(crate) recurrence_frequency: String,
    pub(crate) recurrence_interval: String,
    pub(crate) recurrence_by_day: String,
    pub(crate) recurrence_by_month: String,
    pub(crate) recurrence_by_month_day: String,
    pub(crate) recurrence_by_set_position: String,
    pub(crate) recurrence_first_day_of_week: String,
    pub(crate) recurrence_count: String,
    pub(crate) recurrence_until: String,
    pub(crate) location: String,
    pub(crate) location_locked: bool,
    /// Exact projected value retained when the user does not edit the location,
    /// including encrypted envelopes and multi-field plaintext locations.
    pub(crate) location_source: Option<Value>,
    pub(crate) call_id: String,
    /// JSON array editor preserves attendee roles and display-name snapshots.
    pub(crate) attendees_json: String,
}

impl CalendarCardFields {
    pub(crate) fn has_schedule(&self) -> bool {
        !self.start.trim().is_empty()
            || !self.end.trim().is_empty()
            || !self.timezone.trim().is_empty()
            || self.all_day
            || !self.recurrence_frequency.trim().is_empty()
            || !self.recurrence_interval.trim().is_empty()
            || !self.recurrence_by_day.trim().is_empty()
            || !self.recurrence_by_month.trim().is_empty()
            || !self.recurrence_by_month_day.trim().is_empty()
            || !self.recurrence_by_set_position.trim().is_empty()
            || !self.recurrence_first_day_of_week.trim().is_empty()
            || !self.recurrence_count.trim().is_empty()
            || !self.recurrence_until.trim().is_empty()
            || !self.location.trim().is_empty()
            || self.location_locked
            || !self.call_id.trim().is_empty()
            || !self.attendees_json.trim().is_empty()
    }

    pub(crate) fn has_editable_schedule(&self) -> bool {
        !self.start.trim().is_empty()
            || !self.end.trim().is_empty()
            || !self.timezone.trim().is_empty()
            || self.all_day
            || !self.recurrence_frequency.trim().is_empty()
            || !self.recurrence_interval.trim().is_empty()
            || !self.recurrence_by_day.trim().is_empty()
            || !self.recurrence_by_month.trim().is_empty()
            || !self.recurrence_by_month_day.trim().is_empty()
            || !self.recurrence_by_set_position.trim().is_empty()
            || !self.recurrence_first_day_of_week.trim().is_empty()
            || !self.recurrence_count.trim().is_empty()
            || !self.recurrence_until.trim().is_empty()
            || !self.location.trim().is_empty()
            || !self.call_id.trim().is_empty()
            || !self.attendees_json.trim().is_empty()
    }

    pub(crate) fn recurrence_label(&self) -> String {
        let frequency = self.recurrence_frequency.trim();
        if frequency.is_empty() {
            return String::new();
        }
        let mut parts = vec![frequency.to_owned()];
        if !self.recurrence_interval.trim().is_empty() {
            parts.push(format!("every {}", self.recurrence_interval.trim()));
        }
        if !self.recurrence_by_day.trim().is_empty() {
            parts.push(self.recurrence_by_day.trim().to_owned());
        }
        if !self.recurrence_by_month.trim().is_empty() {
            parts.push(format!("months {}", self.recurrence_by_month.trim()));
        }
        if !self.recurrence_by_month_day.trim().is_empty() {
            parts.push(format!(
                "month days {}",
                self.recurrence_by_month_day.trim()
            ));
        }
        if !self.recurrence_by_set_position.trim().is_empty() {
            parts.push(format!(
                "positions {}",
                self.recurrence_by_set_position.trim()
            ));
        }
        if !self.recurrence_count.trim().is_empty() {
            parts.push(format!("{} times", self.recurrence_count.trim()));
        }
        if !self.recurrence_until.trim().is_empty() {
            parts.push(format!("until {}", self.recurrence_until.trim()));
        }
        parts.join(" · ")
    }
}

/// Reads the schedule out of Strand `metadata.fields`.
///
/// The subtree lives under a single `calendar` namespace, activated by
/// `ak.schema.calendar_event.v1` in `schema_refs`. Flat schedule keys at the
/// `metadata.fields` root are a rejected pre-closure shape, so they are not
/// read back here — treating them as a schedule would resurrect the guess-by
/// -field-presence activation the wire now forbids.
pub(crate) fn calendar_fields_from_metadata(
    fields: &Map<String, Value>,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
    strand_id: &str,
) -> CalendarCardFields {
    static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
    let fields = fields
        .get(arkret_sdk::CALENDAR_METADATA_FIELDS_NAMESPACE)
        .and_then(Value::as_object)
        .unwrap_or(&EMPTY);
    let recurrence = fields.get("recurrence").and_then(Value::as_object);
    let location_value = fields.get("location");
    let (location, location_locked) =
        calendar_location_display_value(location_value, decrypt_ctx, strand_id);
    CalendarCardFields {
        start: fields
            .get("start")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        end: fields
            .get("end")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        timezone: fields
            .get("timezone")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        tzdb_version: fields
            .get("tzdb_version")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_CALENDAR_TZDB_VERSION)
            .to_owned(),
        all_day: fields
            .get("all_day")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        status: fields
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("confirmed")
            .to_owned(),
        recurrence_frequency: recurrence
            .and_then(|value| value.get("frequency"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        recurrence_interval: recurrence
            .and_then(|value| value.get("interval"))
            .and_then(Value::as_u64)
            .map(|value| value.to_string())
            .unwrap_or_default(),
        recurrence_by_day: recurrence
            .and_then(|value| value.get("by_day"))
            .and_then(Value::as_array)
            .map(|days| {
                days.iter()
                    .filter_map(|day| {
                        let weekday = day.get("day").and_then(Value::as_str)?;
                        let nth = day.get("nth_of_period").and_then(Value::as_i64);
                        Some(match nth {
                            Some(nth) => format!("{nth}{}", weekday.to_ascii_uppercase()),
                            None => weekday.to_ascii_uppercase(),
                        })
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        recurrence_by_month: recurrence
            .and_then(|value| value.get("by_month"))
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        recurrence_by_month_day: recurrence
            .and_then(|value| value.get("by_month_day"))
            .and_then(Value::as_array)
            .map(|values| format_integer_array(values))
            .unwrap_or_default(),
        recurrence_by_set_position: recurrence
            .and_then(|value| value.get("by_set_position"))
            .and_then(Value::as_array)
            .map(|values| format_integer_array(values))
            .unwrap_or_default(),
        recurrence_first_day_of_week: recurrence
            .and_then(|value| value.get("first_day_of_week"))
            .and_then(Value::as_str)
            .map(str::to_ascii_uppercase)
            .unwrap_or_default(),
        recurrence_count: recurrence
            .and_then(|value| value.get("count"))
            .and_then(Value::as_u64)
            .map(|value| value.to_string())
            .unwrap_or_default(),
        recurrence_until: recurrence
            .and_then(|value| value.get("until"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        location,
        location_locked,
        location_source: location_value.cloned(),
        call_id: fields
            .get("call_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        attendees_json: fields
            .get("attendees")
            .and_then(Value::as_array)
            .filter(|attendees| !attendees.is_empty())
            .and_then(|attendees| serde_json::to_string(attendees).ok())
            .unwrap_or_default(),
    }
}

fn format_integer_array(values: &[Value]) -> String {
    values
        .iter()
        .filter_map(Value::as_i64)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// True when the touched `metadata.fields` carry the schedule.
///
/// Only the single `calendar` namespace counts. The pre-closure flat keys and
/// the `profile` / `profile_refs` impostors are deliberately excluded: reading
/// them back would reintroduce guess-by-field-presence activation, and a patch
/// that still touches them is a migration unset, not a schedule.
pub(crate) fn fields_have_calendar_keys(fields: &Map<String, Value>) -> bool {
    fields.contains_key(arkret_sdk::CALENDAR_METADATA_FIELDS_NAMESPACE)
}

/// Builds the `ak.strand.update` patch entries for the card's schedule.
///
/// Activation is one canonical pair: `schema_refs` containing
/// `ak.schema.calendar_event.v1` and the whole schedule under
/// `metadata.fields.calendar`. The two are always written and cleared
/// together, because a lone ref or a lone subtree is rejected as
/// `calendar_activation_mismatch` on the post-patch object.
///
/// The pre-closure shape — flat `metadata.fields.start` and friends plus
/// `metadata.fields.profile` / `profile_refs` — is unset here, so a card
/// authored before the closure migrates on its next schedule edit instead of
/// carrying two schedules at once.
pub(crate) fn calendar_patch_entries(
    patch: &mut Map<String, Value>,
    current: &CalendarCardFields,
    draft: &CalendarCardFields,
) -> Result<(), String> {
    const LEGACY_PATHS: &[&str] = &[
        "metadata.fields.profile",
        "metadata.fields.profile_refs",
        "metadata.fields.start",
        "metadata.fields.end",
        "metadata.fields.timezone",
        "metadata.fields.all_day",
        "metadata.fields.recurrence",
        "metadata.fields.attendees",
        "metadata.fields.location",
    ];

    if !current.has_schedule() && !draft.has_editable_schedule() {
        return Ok(());
    }
    if !draft.has_editable_schedule() {
        for path in LEGACY_PATHS {
            patch.insert((*path).to_owned(), json!({ "$op": "unset" }));
        }
        // Ref and subtree are cleared in the same patch: unsetting only one
        // side would leave the object in the mismatch state.
        patch.insert(CALENDAR_SUBTREE_PATH.to_owned(), json!({ "$op": "unset" }));
        patch.insert(
            CALENDAR_SCHEMA_REFS_PATH.to_owned(),
            json!({ "$op": "unset" }),
        );
        return Ok(());
    }

    let event_fields = calendar_event_fields_from_draft(draft)?;
    let event_value = serde_json::to_value(&event_fields)
        .map_err(|err| format!("calendar fields serialize failed: {err}"))?;
    validate_calendar_event_value(&event_value)?;

    for path in LEGACY_PATHS {
        patch.insert((*path).to_owned(), json!({ "$op": "unset" }));
    }
    patch.insert(
        CALENDAR_SCHEMA_REFS_PATH.to_owned(),
        json!({ "$op": "set", "value": [arkret_sdk::SchemaId::CALENDAR_EVENT_V1] }),
    );
    // The subtree is validated as a whole object, so it is written as a whole
    // object rather than field by field. `location` is split back out into its
    // own child path: it is the one schedule member that may be encrypted, and
    // the private-value pipeline encrypts per patch path. The child path sorts
    // after its parent, so the parent object lands first and the encrypted
    // envelope is written on top of it.
    let mut subtree = event_value;
    let location_changed = current.location != draft.location
        || current.location_locked != draft.location_locked
        || current.location_source.is_none() && draft.location_source.is_some();
    let location = location_changed
        .then(|| {
            subtree
                .as_object_mut()
                .and_then(|object| object.remove("location"))
        })
        .flatten();
    patch.insert(
        CALENDAR_SUBTREE_PATH.to_owned(),
        json!({ "$op": "set", "value": subtree }),
    );
    if location_changed {
        set_location_if_changed(patch, current, location, draft.location.trim());
    }
    Ok(())
}

pub(crate) fn calendar_event_fields_from_draft(
    draft: &CalendarCardFields,
) -> Result<arkret_sdk::CalendarEventFields, String> {
    let start = canonical_calendar_date_time(
        "start",
        &required_calendar_field("start", &draft.start)?,
        draft.all_day,
    )?;
    let end = canonical_calendar_date_time(
        "end",
        &required_calendar_field("end", &draft.end)?,
        draft.all_day,
    )?;
    let timezone = required_calendar_field("timezone", &draft.timezone)?;
    validate_calendar_time_order(&start, &end, draft.all_day)?;
    let tzdb_version = if draft.tzdb_version.trim().is_empty() {
        DEFAULT_CALENDAR_TZDB_VERSION.to_owned()
    } else {
        draft.tzdb_version.trim().to_owned()
    };
    let status = calendar_status_from_text(&draft.status)?;
    let fields = arkret_sdk::CalendarEventFields {
        start,
        end,
        timezone,
        tzdb_version,
        all_day: draft.all_day,
        status,
        recurrence: recurrence_from_card(draft)?,
        location: location_value_from_card(draft)?,
        call_id: parse_calendar_call_id(&draft.call_id)?,
        attendees: parse_calendar_attendees(&draft.attendees_json)?,
    };
    fields
        .validate()
        .map_err(|err| format!("calendar schedule is invalid: {err}"))?;
    Ok(fields)
}

fn canonical_calendar_date_time(field: &str, value: &str, all_day: bool) -> Result<String, String> {
    if all_day {
        return value
            .split('T')
            .next()
            .filter(|date| date.len() == 10)
            .map(str::to_owned)
            .ok_or_else(|| format!("calendar {field} must be YYYY-MM-DD"));
    }
    let mut local = value.trim().trim_end_matches('Z').to_owned();
    if let Some(dot) = local.find('.') {
        let suffix = local[dot..].to_owned();
        let offset = suffix
            .find(['+', '-'])
            .map(|index| suffix[index..].to_owned());
        local.truncate(dot);
        if let Some(offset) = offset {
            local.push_str(&offset);
        }
    }
    if let Some(index) = local.rfind('+')
        && index > 10
    {
        local.truncate(index);
    }
    if let Some(index) = local.rfind('-')
        && index > 10
    {
        local.truncate(index);
    }
    (local.len() == 19)
        .then_some(local)
        .ok_or_else(|| format!("calendar {field} must be YYYY-MM-DDTHH:mm:ss"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn calendar_rsvp_operation(
    realm_id: &str,
    actor_id: &str,
    strand_id: &str,
    status: &str,
    occurrence: &str,
    calendar: &CalendarCardFields,
    schedule_basis_refs: Vec<arkret_sdk::Hash>,
    actor_seq: u64,
    hlc: arkret_sdk::Hlc,
) -> anyhow::Result<arkret_sdk::Event> {
    let calendar_fields = calendar_event_fields_from_draft(calendar).map_err(anyhow::Error::msg)?;
    crate::calendar::build_calendar_rsvp_event(
        realm_id,
        actor_id,
        strand_id,
        status,
        (!occurrence.trim().is_empty() && !calendar.recurrence_frequency.trim().is_empty())
            .then_some(occurrence.trim()),
        &calendar_fields,
        schedule_basis_refs,
        actor_seq,
        hlc,
    )
}

pub(crate) fn calendar_schedule_revision_heads(
    events: &[arkret_sdk::Event],
    strand_id: &str,
) -> anyhow::Result<Vec<arkret_sdk::Hash>> {
    let mut by_digest = std::collections::BTreeMap::new();
    let mut revisions = std::collections::BTreeSet::new();
    for event in events {
        let digest = arkret_sdk::Hash::new(event.event_digest()?)?;
        if calendar_event_revises_schedule(event, strand_id) {
            revisions.insert(digest.as_str().to_owned());
        }
        by_digest.insert(digest.as_str().to_owned(), event);
    }
    let mut consumed = std::collections::BTreeSet::new();
    for revision in &revisions {
        let Some(event) = by_digest.get(revision) else {
            continue;
        };
        let mut pending = event
            .causal_refs
            .iter()
            .map(|reference| reference.as_str().to_owned())
            .collect::<Vec<_>>();
        let mut visited = std::collections::BTreeSet::new();
        while let Some(reference) = pending.pop() {
            if !visited.insert(reference.clone()) {
                continue;
            }
            if revisions.contains(&reference) {
                consumed.insert(reference.clone());
            }
            if let Some(ancestor) = by_digest.get(&reference) {
                pending.extend(
                    ancestor
                        .causal_refs
                        .iter()
                        .map(|parent| parent.as_str().to_owned()),
                );
            }
        }
    }
    let heads = revisions
        .difference(&consumed)
        .map(|digest| arkret_sdk::Hash::new(digest.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    if heads.is_empty() {
        anyhow::bail!("calendar schedule has no visible revision head");
    }
    Ok(heads)
}

fn calendar_event_revises_schedule(event: &arkret_sdk::Event, strand_id: &str) -> bool {
    match event.kind.as_str() {
        "ak.strand.create" => {
            let object = event.payload.get("object");
            object
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str)
                == Some(strand_id)
                && object
                    .and_then(|object| object.get("metadata"))
                    .and_then(|metadata| metadata.get("fields"))
                    .and_then(Value::as_object)
                    .is_some_and(fields_have_calendar_keys)
        }
        "ak.strand.update" => {
            event.payload.get("target_ref").and_then(Value::as_str) == Some(strand_id)
                && event
                    .payload
                    .get("patch")
                    .and_then(Value::as_object)
                    .is_some_and(calendar_patch_revises_schedule)
        }
        _ => false,
    }
}

fn calendar_patch_revises_schedule(patch: &Map<String, Value>) -> bool {
    patch.iter().any(|(path, value)| {
        if path == CALENDAR_SUBTREE_PATH || path.starts_with(&format!("{CALENDAR_SUBTREE_PATH}.")) {
            return true;
        }
        if path == "metadata.fields" {
            return value
                .get("value")
                .or_else(|| value.get("$value"))
                .or_else(|| value.get("fields"))
                .or(Some(value))
                .and_then(Value::as_object)
                .is_some_and(fields_have_calendar_keys);
        }
        if path == "metadata" {
            return value
                .get("value")
                .or_else(|| value.get("$value"))
                .and_then(|metadata| metadata.get("fields"))
                .and_then(Value::as_object)
                .is_some_and(fields_have_calendar_keys);
        }
        false
    })
}

/// Canonical instance key for the card's base occurrence.
///
/// Timed schedules now carry a whole-second `LocalDateTime` in the event
/// timezone, so the key is that value plus the zone — no instant conversion.
/// The pre-closure wire carried a UTC instant here, and stripping its `Z`
/// produced a key in the wrong wall clock; that whole failure mode is gone
/// because the schedule no longer stores an absolute instant.
pub(crate) fn calendar_occurrence_hint(calendar: &CalendarCardFields) -> String {
    let start = calendar.start.trim();
    if start.is_empty() {
        return String::new();
    }
    if calendar.all_day {
        return start.split('T').next().unwrap_or(start).to_owned();
    }
    let timezone = calendar.timezone.trim();
    if timezone.is_empty() {
        return start.to_owned();
    }
    format!("{start}[{timezone}]")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CalendarAgendaItem {
    pub(crate) occurrence: String,
    pub(crate) local_start: String,
    pub(crate) local_end: String,
}

/// Expands the next 90 days through the shared Calendar time API. The UI never
/// slices schedule strings or reimplements recurrence/TZDB/DST behavior.
pub(crate) fn calendar_agenda(
    calendar: &CalendarCardFields,
    schedule_revision_heads: &[String],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<CalendarAgendaItem>, String> {
    let fields = calendar_event_fields_from_draft(calendar)?;
    let mut heads = schedule_revision_heads
        .iter()
        .map(|head| arkret_sdk::Hash::new(head.clone()).map_err(|err| err.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    heads.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    heads.dedup_by(|left, right| left.as_str() == right.as_str());
    if heads.is_empty() {
        return Err("calendar agenda requires an observed schedule frontier".to_owned());
    }
    let page = fields
        .expand_occurrences_between_instants(now, now + chrono::Duration::days(90), 20, heads)
        .map_err(|err| err.to_string())?;
    Ok(page
        .occurrences
        .into_iter()
        .map(|occurrence| CalendarAgendaItem {
            occurrence: occurrence.occurrence,
            local_start: occurrence.local_start,
            local_end: occurrence.local_end,
        })
        .collect())
}

fn calendar_status_from_text(value: &str) -> Result<arkret_sdk::CalendarStatus, String> {
    match value.trim() {
        "" | "confirmed" => Ok(arkret_sdk::CalendarStatus::Confirmed),
        "tentative" => Ok(arkret_sdk::CalendarStatus::Tentative),
        "cancelled" => Ok(arkret_sdk::CalendarStatus::Cancelled),
        other => Err(format!("unknown calendar status: {other}")),
    }
}

fn required_calendar_field(field: &str, value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(format!("calendar {field} is required"))
    } else {
        Ok(trimmed.to_owned())
    }
}

fn validate_calendar_time_order(start: &str, end: &str, all_day: bool) -> Result<(), String> {
    if all_day {
        let start = chrono::NaiveDate::parse_from_str(start, "%Y-%m-%d")
            .map_err(|err| format!("all-day calendar start must be YYYY-MM-DD: {err}"))?;
        let end = chrono::NaiveDate::parse_from_str(end, "%Y-%m-%d")
            .map_err(|err| format!("all-day calendar end must be YYYY-MM-DD: {err}"))?;
        // The interval is half-open [start, end), so a single-day event spells
        // end as the following date.
        if end <= start {
            return Err(
                "all-day calendar end must be strictly later than start; a single-day event uses the following date"
                    .to_owned(),
            );
        }
        return Ok(());
    }
    // Timed anchors are whole-second LocalDateTime in the event timezone; the
    // wire no longer carries an absolute instant here.
    let start_dt = chrono::NaiveDateTime::parse_from_str(start, "%Y-%m-%dT%H:%M:%S")
        .map_err(|err| format!("calendar start must be YYYY-MM-DDTHH:mm:ss: {err}"))?;
    let end_dt = chrono::NaiveDateTime::parse_from_str(end, "%Y-%m-%dT%H:%M:%S")
        .map_err(|err| format!("calendar end must be YYYY-MM-DDTHH:mm:ss: {err}"))?;
    if end_dt <= start_dt {
        return Err("calendar end must be after start".to_owned());
    }
    Ok(())
}

fn recurrence_from_card(
    calendar: &CalendarCardFields,
) -> Result<Option<arkret_sdk::CalendarRecurrence>, String> {
    let frequency = calendar.recurrence_frequency.trim();
    let has_recurrence = !frequency.is_empty()
        || !calendar.recurrence_interval.trim().is_empty()
        || !calendar.recurrence_by_day.trim().is_empty()
        || !calendar.recurrence_by_month.trim().is_empty()
        || !calendar.recurrence_by_month_day.trim().is_empty()
        || !calendar.recurrence_by_set_position.trim().is_empty()
        || !calendar.recurrence_first_day_of_week.trim().is_empty()
        || !calendar.recurrence_count.trim().is_empty()
        || !calendar.recurrence_until.trim().is_empty();
    if !has_recurrence {
        return Ok(None);
    }
    let frequency = parse_recurrence_frequency(frequency)?;
    let interval = parse_optional_u64("recurrence interval", &calendar.recurrence_interval)?;
    let by_day = parse_recurrence_weekdays(&calendar.recurrence_by_day)?;
    let by_month =
        parse_optional_string_list("recurrence by_month", &calendar.recurrence_by_month)?;
    let by_month_day = parse_optional_integer_list::<i8>(
        "recurrence by_month_day",
        &calendar.recurrence_by_month_day,
    )?;
    let by_set_position = parse_optional_integer_list::<i16>(
        "recurrence by_set_position",
        &calendar.recurrence_by_set_position,
    )?;
    let first_day_of_week =
        parse_optional_recurrence_weekday(&calendar.recurrence_first_day_of_week)?;
    let count = parse_optional_u64("recurrence count", &calendar.recurrence_count)?;
    if let Some(count) = count
        && !(1..=10_000).contains(&count)
    {
        return Err("recurrence count must be between 1 and 10000".to_owned());
    }
    let until = calendar.recurrence_until.trim();
    let until = if until.is_empty() {
        None
    } else {
        if until.ends_with('Z') || until.contains('+') {
            return Err("recurrence until must not contain a UTC offset or Z suffix".to_owned());
        }
        if calendar.all_day {
            chrono::NaiveDate::parse_from_str(until, "%Y-%m-%d")
                .map_err(|err| format!("all-day recurrence until must be a date: {err}"))?;
        } else {
            chrono::NaiveDateTime::parse_from_str(until, "%Y-%m-%dT%H:%M:%S").map_err(|err| {
                format!("recurrence until must be a whole-second local date-time: {err}")
            })?;
        }
        Some(until.to_owned())
    };
    if count.is_some() && until.is_some() {
        return Err("recurrence count and until are mutually exclusive".to_owned());
    }
    Ok(Some(arkret_sdk::CalendarRecurrence {
        frequency,
        interval,
        by_day,
        by_month,
        by_month_day,
        by_set_position,
        first_day_of_week,
        count,
        until,
    }))
}

fn parse_recurrence_frequency(value: &str) -> Result<arkret_sdk::RecurrenceFrequency, String> {
    match value.trim().to_ascii_uppercase().as_str() {
        "DAILY" => Ok(arkret_sdk::RecurrenceFrequency::Daily),
        "WEEKLY" => Ok(arkret_sdk::RecurrenceFrequency::Weekly),
        "MONTHLY" => Ok(arkret_sdk::RecurrenceFrequency::Monthly),
        "YEARLY" => Ok(arkret_sdk::RecurrenceFrequency::Yearly),
        _ => Err("recurrence frequency must be DAILY, WEEKLY, MONTHLY, or YEARLY".to_owned()),
    }
}

fn parse_recurrence_weekdays(
    value: &str,
) -> Result<Vec<arkret_sdk::CalendarRecurrenceDay>, String> {
    let mut days = Vec::new();
    for day in value
        .split(',')
        .map(|day| day.trim().to_ascii_uppercase())
        .filter(|day| !day.is_empty())
    {
        if day.len() < 2 {
            return Err(format!("unsupported recurrence weekday {day}"));
        }
        let (nth, weekday) = day.split_at(day.len() - 2);
        let parsed = match weekday {
            "MO" => arkret_sdk::RecurrenceWeekday::Mo,
            "TU" => arkret_sdk::RecurrenceWeekday::Tu,
            "WE" => arkret_sdk::RecurrenceWeekday::We,
            "TH" => arkret_sdk::RecurrenceWeekday::Th,
            "FR" => arkret_sdk::RecurrenceWeekday::Fr,
            "SA" => arkret_sdk::RecurrenceWeekday::Sa,
            "SU" => arkret_sdk::RecurrenceWeekday::Su,
            _ => return Err(format!("unsupported recurrence weekday {day}")),
        };
        let nth_of_period = if nth.is_empty() {
            None
        } else {
            let value = nth
                .parse::<i16>()
                .map_err(|err| format!("invalid recurrence ordinal {nth}: {err}"))?;
            if value == 0 || !(-366..=366).contains(&value) {
                return Err("recurrence ordinal must be in -366..=-1 or 1..=366".to_owned());
            }
            Some(value)
        };
        let parsed = arkret_sdk::CalendarRecurrenceDay {
            day: parsed,
            nth_of_period,
        };
        if days.contains(&parsed) {
            return Err(format!("duplicate recurrence by_day value {day}"));
        }
        days.push(parsed);
    }
    Ok(days)
}

fn parse_optional_recurrence_weekday(
    value: &str,
) -> Result<Option<arkret_sdk::RecurrenceWeekday>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = parse_recurrence_weekdays(value)?;
    if parsed.len() != 1 || parsed[0].nth_of_period.is_some() {
        return Err("first_day_of_week must be one of MO, TU, WE, TH, FR, SA, SU".to_owned());
    }
    Ok(Some(parsed[0].day))
}

fn parse_optional_string_list(field: &str, value: &str) -> Result<Option<Vec<String>>, String> {
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(None);
    }
    let unique = values.iter().collect::<std::collections::BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{field} must not contain duplicates"));
    }
    Ok(Some(values))
}

fn parse_optional_integer_list<T>(field: &str, value: &str) -> Result<Option<Vec<T>>, String>
where
    T: std::str::FromStr + Ord + Copy,
    T::Err: std::fmt::Display,
{
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|err| format!("{field} contains an invalid integer {value}: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        return Ok(None);
    }
    let unique = values
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{field} must not contain duplicates"));
    }
    Ok(Some(values))
}

fn parse_optional_u64(field: &str, value: &str) -> Result<Option<u64>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed = trimmed
        .parse::<u64>()
        .map_err(|err| format!("{field} must be an integer: {err}"))?;
    if parsed == 0 {
        return Err(format!("{field} must be at least 1"));
    }
    Ok(Some(parsed))
}

fn location_value_from_card(
    calendar: &CalendarCardFields,
) -> Result<Option<arkret_sdk::CalendarEventLocation>, String> {
    if let Some(source) = &calendar.location_source {
        let source_label = calendar_location_plaintext_label(source);
        if calendar.location_locked || source_label == calendar.location.trim() {
            return serde_json::from_value(source.clone())
                .map(Some)
                .map_err(|err| format!("projected calendar location is invalid: {err}"));
        }
    }
    Ok(location_value_from_text(&calendar.location))
}

fn location_value_from_text(value: &str) -> Option<arkret_sdk::CalendarEventLocation> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| {
        arkret_sdk::CalendarEventLocation::Plaintext(arkret_sdk::CalendarLocation {
            title: Some(trimmed.to_owned()),
            address: None,
            geo_uri: None,
            url: None,
        })
    })
}

fn parse_calendar_call_id(value: &str) -> Result<Option<arkret_sdk::CallId>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    arkret_sdk::CallId::new(value.to_owned())
        .map(Some)
        .map_err(|err| format!("calendar call_id is invalid: {err}"))
}

fn parse_calendar_attendees(value: &str) -> Result<Vec<arkret_sdk::CalendarAttendee>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(value)
        .map_err(|err| format!("calendar attendees must be a JSON array: {err}"))
}

fn location_json_from_text(value: &str) -> Option<Value> {
    location_value_from_text(value)
        .map(serde_json::to_value)
        .transpose()
        .ok()
        .flatten()
}

fn calendar_location_display_value(
    value: Option<&Value>,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
    strand_id: &str,
) -> (String, bool) {
    let Some(value) = value else {
        return (String::new(), false);
    };
    if value_is_mls_envelope(value) {
        if let Some(ctx) = decrypt_ctx
            && let Some(plaintext) = ctx.state_store.private_plaintext_for(
                ctx.realm_id,
                strand_id,
                CALENDAR_LOCATION_PRIVATE_PATH,
            )
            && let Ok(parsed) = serde_json::from_str::<Value>(&plaintext)
        {
            return (calendar_location_plaintext_label(&parsed), false);
        }
        if let Some(parsed) = decrypt_ctx.and_then(|ctx| decrypt_private_strand_value(ctx, value)) {
            return (calendar_location_plaintext_label(&parsed), false);
        }
        return (String::new(), true);
    }
    (calendar_location_plaintext_label(value), false)
}

fn calendar_location_plaintext_label(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.trim().to_owned();
    }
    let Some(object) = value.as_object() else {
        return String::new();
    };
    ["title", "address", "url", "geo_uri"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_owned()
}

fn validate_calendar_event_value(value: &Value) -> Result<(), String> {
    arkret_sdk::ProtocolSchemaRegistry::default()
        .validate_value(arkret_sdk::SchemaId::CALENDAR_EVENT_V1, value)
        .map_err(|err| format!("calendar schedule does not match schema: {err}"))
}

fn set_if_changed(
    patch: &mut Map<String, Value>,
    path: &str,
    current: Option<Value>,
    next: Option<Value>,
) {
    if current == next {
        return;
    }
    match next {
        Some(value) => {
            patch.insert(path.to_owned(), json!({ "$op": "set", "value": value }));
        }
        None => {
            patch.insert(path.to_owned(), json!({ "$op": "unset" }));
        }
    }
}

fn set_location_if_changed(
    patch: &mut Map<String, Value>,
    current: &CalendarCardFields,
    next: Option<Value>,
    draft_location: &str,
) {
    if current.location_locked && draft_location.is_empty() {
        return;
    }
    let current_value = location_json_from_text(&current.location);
    set_if_changed(patch, CALENDAR_LOCATION_PRIVATE_PATH, current_value, next);
}

/// Card-level RSVP display state.
///
/// Built from the shared SDK projection so the client classifies heads exactly
/// like the server and the conformance runner. Concurrent answers are surfaced
/// as a conflict the responder must resolve; nothing here silently picks one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CalendarRsvpDisplay {
    /// The signed-in actor's effective answer, if it has one.
    pub(crate) own_status: Option<String>,
    /// The actor answered concurrently and the answers disagree.
    pub(crate) own_conflicted: bool,
    /// A significant schedule field moved since the actor answered.
    pub(crate) own_needs_reconfirmation: bool,
    /// Aggregate of every responder's effective answer.
    pub(crate) accepted: usize,
    pub(crate) declined: usize,
    pub(crate) tentative: usize,
    /// Heads that exist but do not count: orphaned by an identity-affecting
    /// edit, unreadable, or resting on an unknown schedule basis.
    pub(crate) excluded: usize,
}

impl CalendarRsvpDisplay {
    pub(crate) fn has_any(&self) -> bool {
        self.own_status.is_some()
            || self.accepted + self.declined + self.tentative + self.excluded > 0
    }
}

/// Folds the projected RSVP cells into the card display model.
///
/// `occurrence` is the instance the card is showing, or `None` for the series.
/// Instance answers override the series fallback and the two are never unioned.
pub(crate) fn calendar_rsvp_display(
    cells: &[crate::state::projection_views::RsvpCellProjectionView],
    schedule_revision_heads: &[String],
    occurrence: Option<&str>,
    self_actor_id: &str,
) -> CalendarRsvpDisplay {
    let frontier = arkret_sdk::CalendarScheduleProjection::from_heads(
        &schedule_revision_heads
            .iter()
            .filter_map(|value| arkret_sdk::Hash::new(value.clone()).ok())
            .map(|digest| (digest, Some(Vec::new())))
            .collect::<Vec<_>>(),
    );

    let mut display = CalendarRsvpDisplay::default();
    let mut by_actor: std::collections::BTreeMap<String, arkret_sdk::CalendarRsvpProjection> =
        std::collections::BTreeMap::new();
    for cell in cells {
        let is_instance = cell.occurrence.is_some();
        // A cell for another instance says nothing about this one.
        if is_instance && cell.occurrence.as_deref() != occurrence {
            continue;
        }
        let entry = by_actor.entry(cell.actor_id.clone()).or_insert_with(|| {
            arkret_sdk::CalendarRsvpProjection {
                instance_heads: Vec::new(),
                series_heads: Vec::new(),
            }
        });
        for head in &cell.heads {
            let Some(classified) = classify_rsvp_head(head, &frontier, is_instance) else {
                continue;
            };
            if is_instance {
                entry.instance_heads.push(classified);
            } else {
                entry.series_heads.push(classified);
            }
        }
    }

    for (actor_id, projection) in &by_actor {
        display.excluded += projection.excluded_heads().len();
        let conflicted = projection.resolution_state() == arkret_sdk::RsvpResolutionState::Conflict;
        let needs_reconfirmation = projection.effective_heads().iter().any(|head| {
            head.basis_class == arkret_sdk::RsvpBasisClass::EffectiveNeedsReconfirmation
        });
        let status = projection
            .effective_response()
            .map(|response| rsvp_status_text(response.status));
        if actor_id == self_actor_id {
            display.own_status = status.clone();
            display.own_conflicted = conflicted;
            display.own_needs_reconfirmation = needs_reconfirmation;
        }
        // A responder with an unresolved conflict has no single answer, so they
        // are not counted into any aggregate bucket.
        match status.as_deref() {
            Some("accepted") => display.accepted += 1,
            Some("declined") => display.declined += 1,
            Some("tentative") => display.tentative += 1,
            _ => {}
        }
    }
    display
}

fn classify_rsvp_head(
    head: &crate::state::projection_views::RsvpHeadProjectionView,
    frontier: &arkret_sdk::CalendarScheduleProjection,
    is_instance: bool,
) -> Option<arkret_sdk::CalendarRsvpHead> {
    let source_event_digest = arkret_sdk::Hash::new(head.source_event_digest.clone()).ok()?;
    let entry = serde_json::from_value::<arkret_sdk::RsvpEntry>(head.entry.clone()).ok()?;
    // The plaintext branch is readable directly; an encrypted branch this
    // device cannot open is listed without fabricating a status.
    let (response, response_class) = match (&entry.response, &entry.encrypted_response) {
        (Some(response), None) => (
            Some(response.clone()),
            arkret_sdk::RsvpResponseClass::Resolved,
        ),
        (None, Some(_)) => (None, arkret_sdk::RsvpResponseClass::EncryptedUnresolved),
        _ => (None, arkret_sdk::RsvpResponseClass::InvalidResponse),
    };
    let basis_class = arkret_sdk::CalendarRsvpHead::classify_basis(
        &entry.schedule_basis_refs,
        &frontier.schedule_revision_heads,
        is_instance,
        false,
        false,
    );
    Some(arkret_sdk::CalendarRsvpHead {
        source_event_digest,
        schedule_basis_refs: entry.schedule_basis_refs,
        response,
        basis_class,
        response_class,
    })
}

fn rsvp_status_text(status: arkret_sdk::RsvpStatus) -> String {
    match status {
        arkret_sdk::RsvpStatus::Accepted => "accepted",
        arkret_sdk::RsvpStatus::Declined => "declined",
        arkret_sdk::RsvpStatus::Tentative => "tentative",
    }
    .to_owned()
}
