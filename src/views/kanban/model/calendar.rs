use super::*;

pub(crate) const CALENDAR_PROFILE_FIELD: &str = "profile";
pub(crate) const CALENDAR_PROFILE_REFS_FIELD: &str = "profile_refs";
pub(crate) const CALENDAR_LOCATION_PRIVATE_PATH: &str = "metadata.fields.location";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CalendarCardFields {
    pub(crate) start: String,
    pub(crate) end: String,
    pub(crate) timezone: String,
    pub(crate) all_day: bool,
    pub(crate) recurrence_frequency: String,
    pub(crate) recurrence_interval: String,
    pub(crate) recurrence_by_day: String,
    pub(crate) recurrence_count: String,
    pub(crate) recurrence_until: String,
    pub(crate) location: String,
    pub(crate) location_locked: bool,
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
            || !self.recurrence_count.trim().is_empty()
            || !self.recurrence_until.trim().is_empty()
            || !self.location.trim().is_empty()
            || self.location_locked
    }

    pub(crate) fn has_editable_schedule(&self) -> bool {
        !self.start.trim().is_empty()
            || !self.end.trim().is_empty()
            || !self.timezone.trim().is_empty()
            || self.all_day
            || !self.recurrence_frequency.trim().is_empty()
            || !self.recurrence_interval.trim().is_empty()
            || !self.recurrence_by_day.trim().is_empty()
            || !self.recurrence_count.trim().is_empty()
            || !self.recurrence_until.trim().is_empty()
            || !self.location.trim().is_empty()
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
        if !self.recurrence_count.trim().is_empty() {
            parts.push(format!("{} times", self.recurrence_count.trim()));
        }
        if !self.recurrence_until.trim().is_empty() {
            parts.push(format!("until {}", self.recurrence_until.trim()));
        }
        parts.join(" · ")
    }
}

pub(crate) fn calendar_fields_from_metadata(
    fields: &Map<String, Value>,
    decrypt_ctx: Option<&MlsDecryptCtx<'_>>,
    strand_id: &str,
) -> CalendarCardFields {
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
        all_day: fields
            .get("all_day")
            .and_then(Value::as_bool)
            .unwrap_or(false),
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
                    .filter_map(|day| day.get("day").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
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
    }
}

pub(crate) fn fields_have_calendar_keys(fields: &Map<String, Value>) -> bool {
    [
        CALENDAR_PROFILE_FIELD,
        CALENDAR_PROFILE_REFS_FIELD,
        "start",
        "end",
        "timezone",
        "all_day",
        "recurrence",
        "location",
    ]
    .iter()
    .any(|key| fields.contains_key(*key))
}

pub(crate) fn calendar_patch_entries(
    patch: &mut Map<String, Value>,
    current: &CalendarCardFields,
    draft: &CalendarCardFields,
) -> Result<(), String> {
    if !current.has_schedule() && !draft.has_editable_schedule() {
        return Ok(());
    }
    if !draft.has_editable_schedule() {
        for path in [
            "metadata.fields.profile",
            "metadata.fields.profile_refs",
            "metadata.fields.start",
            "metadata.fields.end",
            "metadata.fields.timezone",
            "metadata.fields.all_day",
            "metadata.fields.recurrence",
            "metadata.fields.location",
        ] {
            patch.insert(path.to_owned(), json!({ "$op": "unset" }));
        }
        return Ok(());
    }

    let event_fields = calendar_event_fields_from_draft(draft)?;
    let event_value = serde_json::to_value(&event_fields)
        .map_err(|err| format!("calendar fields serialize failed: {err}"))?;
    validate_calendar_event_value(&event_value)?;

    set_if_changed(
        patch,
        "metadata.fields.profile",
        current_profile_value(current),
        Some(json!(arkret_sdk::PROFILE_CALENDAR_EVENT)),
    );
    set_if_changed(
        patch,
        "metadata.fields.profile_refs",
        current_profile_refs_value(current),
        Some(json!([arkret_sdk::PROFILE_CALENDAR_EVENT])),
    );
    set_string_if_changed(patch, "metadata.fields.start", &current.start, &draft.start);
    set_string_if_changed(patch, "metadata.fields.end", &current.end, &draft.end);
    set_string_if_changed(
        patch,
        "metadata.fields.timezone",
        &current.timezone,
        &draft.timezone,
    );
    if current.all_day != draft.all_day {
        patch.insert(
            "metadata.fields.all_day".to_owned(),
            json!({ "$op": "set", "value": draft.all_day }),
        );
    }
    set_value_if_changed(
        patch,
        "metadata.fields.recurrence",
        recurrence_value_from_card(current)?,
        event_value.get("recurrence").cloned(),
    );
    set_location_if_changed(
        patch,
        current,
        event_value.get("location").cloned(),
        draft.location.trim(),
    );
    Ok(())
}

pub(crate) fn calendar_event_fields_from_draft(
    draft: &CalendarCardFields,
) -> Result<arkret_sdk::CalendarEventFields, String> {
    let start = required_calendar_field("start", &draft.start)?;
    let end = required_calendar_field("end", &draft.end)?;
    let timezone = required_calendar_field("timezone", &draft.timezone)?;
    validate_calendar_time_order(&start, &end, draft.all_day)?;
    Ok(arkret_sdk::CalendarEventFields {
        start,
        end,
        timezone,
        all_day: draft.all_day,
        recurrence: recurrence_from_card(draft)?,
        location: location_value_from_text(&draft.location),
        call_id: None,
        attendees: Vec::new(),
    })
}

pub(crate) fn calendar_rsvp_operation(
    realm_id: &str,
    actor_id: &str,
    strand_id: &str,
    status: &str,
    occurrence: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    crate::operation::ak_ops::rsvp_set(
        realm_id,
        actor_id,
        strand_id,
        status,
        (!occurrence.trim().is_empty()).then_some(occurrence.trim()),
        None,
    )
    .and_then(|builder| builder.build_sdk_event("inkson"))
}

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
    let mut local_like = start.trim_end_matches('Z');
    if let Some(index) = local_like.rfind('+')
        && index > 10
    {
        local_like = &local_like[..index];
    }
    if let Some(index) = local_like.rfind('-')
        && index > 10
    {
        local_like = &local_like[..index];
    }
    format!("{local_like}[{timezone}]")
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
        if end < start {
            return Err("all-day calendar end must be on or after start".to_owned());
        }
        return Ok(());
    }
    let start_dt = chrono::DateTime::parse_from_rfc3339(start)
        .map_err(|err| format!("calendar start must be RFC3339: {err}"))?;
    let end_dt = chrono::DateTime::parse_from_rfc3339(end)
        .map_err(|err| format!("calendar end must be RFC3339: {err}"))?;
    if !start.ends_with('Z') {
        return Err("calendar start must be UTC RFC3339 ending in Z".to_owned());
    }
    if !end.ends_with('Z') {
        return Err("calendar end must be UTC RFC3339 ending in Z".to_owned());
    }
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
        || !calendar.recurrence_count.trim().is_empty()
        || !calendar.recurrence_until.trim().is_empty();
    if !has_recurrence {
        return Ok(None);
    }
    let frequency = parse_recurrence_frequency(frequency)?;
    let interval = parse_optional_u64("recurrence interval", &calendar.recurrence_interval)?;
    let by_day = parse_recurrence_weekdays(&calendar.recurrence_by_day)?;
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
        chrono::NaiveDateTime::parse_from_str(until, "%Y-%m-%dT%H:%M:%S%.f")
            .map_err(|err| format!("recurrence until must be a local date-time: {err}"))?;
        Some(until.to_owned())
    };
    if count.is_some() && until.is_some() {
        return Err("recurrence count and until are mutually exclusive".to_owned());
    }
    Ok(Some(arkret_sdk::CalendarRecurrence {
        frequency,
        interval,
        by_day,
        by_month: None,
        by_month_day: None,
        by_set_position: None,
        first_day_of_week: None,
        count,
        until,
    }))
}

fn recurrence_value_from_card(calendar: &CalendarCardFields) -> Result<Option<Value>, String> {
    recurrence_from_card(calendar)?
        .map(serde_json::to_value)
        .transpose()
        .map_err(|err| format!("recurrence serialize failed: {err}"))
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
        let parsed = match day.as_str() {
            "MO" => arkret_sdk::RecurrenceWeekday::Mo,
            "TU" => arkret_sdk::RecurrenceWeekday::Tu,
            "WE" => arkret_sdk::RecurrenceWeekday::We,
            "TH" => arkret_sdk::RecurrenceWeekday::Th,
            "FR" => arkret_sdk::RecurrenceWeekday::Fr,
            "SA" => arkret_sdk::RecurrenceWeekday::Sa,
            "SU" => arkret_sdk::RecurrenceWeekday::Su,
            _ => return Err(format!("unsupported recurrence weekday {day}")),
        };
        let parsed = arkret_sdk::CalendarRecurrenceDay {
            day: parsed,
            nth_of_period: None,
        };
        if !days.contains(&parsed) {
            days.push(parsed);
        }
    }
    Ok(days)
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
        .validate_value(arkret_sdk::CALENDAR_EVENT_SCHEMA, value)
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

fn set_value_if_changed(
    patch: &mut Map<String, Value>,
    path: &str,
    current: Option<Value>,
    next: Option<Value>,
) {
    set_if_changed(patch, path, current, next);
}

fn set_string_if_changed(patch: &mut Map<String, Value>, path: &str, current: &str, next: &str) {
    let current = (!current.trim().is_empty()).then(|| json!(current.trim()));
    let next = (!next.trim().is_empty()).then(|| json!(next.trim()));
    set_if_changed(patch, path, current, next);
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

fn current_profile_value(current: &CalendarCardFields) -> Option<Value> {
    current
        .has_schedule()
        .then(|| json!(arkret_sdk::PROFILE_CALENDAR_EVENT))
}

fn current_profile_refs_value(current: &CalendarCardFields) -> Option<Value> {
    current
        .has_schedule()
        .then(|| json!([arkret_sdk::PROFILE_CALENDAR_EVENT]))
}
